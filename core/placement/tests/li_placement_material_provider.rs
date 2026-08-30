// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::time::Duration;

use li_core_interface::{
    CredentialId, DeviceId, EndpointAddress, EndpointHealth, EndpointOwnership, EndpointScheme,
    EntityTimestamps, NodeAddress, NodeId, Placement, PlacementAssignment, PlacementEndpoint,
    PlacementGroupId, PlacementId, PlacementResources, PlacementState, PortRange,
    RuntimeInstallationId, RuntimeSource, Sha256Digest, TaskId, UnixMilliseconds,
};
use li_placement_manager::{
    FilesystemPlacementMaterialProvider, FilesystemPlacementMaterialReader,
    LinuxContainerLaunchPlan, LinuxContainerReadiness, LinuxPlacementMaterialProvider,
    MacosLaunchAgentPlan, MacosPlacementMaterialProvider, PlacementCredentialDisposition,
    PlacementCredentialProvider, PlacementCredentialProvision, PlacementCredentialReferences,
    PlacementError, PlacementLaunchPlanIdentityProvider, PlacementLaunchPlanResolver,
    PlacementMaterialIdentityProvider, PlacementMaterialIo, ResolvedPlacementLaunchPlan,
    ShellFreeCommand, ShellFreeEnvironmentValue, SystemPlacementMaterialIdentityProvider,
    SystemPlacementMaterialIo,
};
use li_runtime_manager::RuntimeExecutionImageReference;
use sha2::{Digest, Sha256};

const PLAN_FILE: &str = "li_placement_launch_plan_v3.json";
const DIGEST_FILE: &str = "li_placement_launch_plan_v3.sha256";

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
                None,
            )
            .expect("resources"),
            if endpoint_owner {
                EndpointOwnership::Owner
            } else {
                EndpointOwnership::Participant
            },
        ),
        PlacementState::Staged,
        None,
        None,
        EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(1_000))
            .expect("timestamps"),
    )
    .expect("placement")
}

// Returns one exact endpoint carrying credential references only.
fn endpoint(placement: &Placement) -> PlacementEndpoint {
    PlacementEndpoint::new(
        placement.placement_id().clone(),
        placement.assignment().node_id().clone(),
        EndpointAddress::new(
            EndpointScheme::Https,
            placement.assignment().address().clone(),
            18_000,
        )
        .expect("address"),
        CredentialId::parse(&"5".repeat(32)).expect("credential"),
        Some(CredentialId::parse(&"6".repeat(32)).expect("CA")),
        None,
        4,
        262_144,
        EndpointHealth::new(true, false, None, Vec::new()).expect("health"),
    )
    .expect("endpoint")
}

// Returns one reference-only credential fixture matching plan endpoint identities.
fn credential_references(placement: &Placement) -> PlacementCredentialReferences {
    PlacementCredentialReferences::new(
        placement.placement_id().clone(),
        CredentialId::parse(&"5".repeat(32)).expect("credential"),
        CredentialId::parse(&"6".repeat(32)).expect("CA"),
        PathBuf::from("/private/engine.key"),
        PathBuf::from("/private/engine.crt"),
        PathBuf::from("/private/engine-tls.key"),
        Sha256Digest::parse(&"7".repeat(64)).expect("certificate digest"),
        Sha256Digest::parse(&"8".repeat(64)).expect("bundle digest"),
    )
    .expect("credential references")
}

// Returns one exact Docker command whose host environment is Core-owned.
fn docker_command(placement: &Placement) -> ShellFreeCommand {
    let image = format!("ghcr.io/letsinferlabs/engine@sha256:{}", "a".repeat(64));
    docker_command_for_image(placement, image)
}

// Returns one exact Docker command for a caller-selected immutable execution identity.
fn docker_command_for_image(placement: &Placement, image: String) -> ShellFreeCommand {
    let name = format!("li_placement_{}", placement.placement_id().as_str());
    let mut arguments = vec![
        "run".to_string(),
        "--detach".to_string(),
        "--name".to_string(),
        name,
        "--restart".to_string(),
        "no".to_string(),
        "--log-driver".to_string(),
        "local".to_string(),
        "--log-opt".to_string(),
        "max-size=8m".to_string(),
        "--log-opt".to_string(),
        "max-file=2".to_string(),
    ];
    for (key, value) in [
        ("ai.letsinfer.managed", "true".to_string()),
        (
            "ai.letsinfer.placement_group_id",
            placement.placement_group_id().as_str().to_string(),
        ),
        (
            "ai.letsinfer.placement_id",
            placement.placement_id().as_str().to_string(),
        ),
        (
            "ai.letsinfer.node_id",
            placement.assignment().node_id().as_str().to_string(),
        ),
        (
            "ai.letsinfer.task_id",
            placement.assignment().task_id().as_str().to_string(),
        ),
    ] {
        arguments.extend(["--label".to_string(), format!("{key}={value}")]);
    }
    arguments.extend([image, "/opt/letsinfer/bin/engine-adapter".to_string()]);
    ShellFreeCommand::new(
        PathBuf::from("/usr/bin/docker"),
        arguments,
        Vec::new(),
        vec![
            ShellFreeEnvironmentValue::core("HOME", "/home/fixture").expect("home"),
            ShellFreeEnvironmentValue::core("PATH", "/usr/bin:/bin").expect("path"),
            ShellFreeEnvironmentValue::protected("LETSINFER_API_KEY_FILE", "/private/engine.key")
                .expect("credential file"),
            ShellFreeEnvironmentValue::protected("LETSINFER_TLS_CERT_FILE", "/private/engine.crt")
                .expect("certificate file"),
            ShellFreeEnvironmentValue::protected(
                "LETSINFER_TLS_KEY_FILE",
                "/private/engine-tls.key",
            )
            .expect("private key file"),
            ShellFreeEnvironmentValue::protected(
                "LETSINFER_CREDENTIAL_BUNDLE_SHA256",
                &"8".repeat(64),
            )
            .expect("bundle digest"),
        ],
        PathBuf::from("/tmp"),
    )
    .expect("Docker command")
}

// Returns one complete Linux launch plan fixture.
fn linux_plan(placement: &Placement) -> ResolvedPlacementLaunchPlan {
    ResolvedPlacementLaunchPlan::Linux(
        LinuxContainerLaunchPlan::new(
            placement,
            RuntimeSource::parse(&format!(
                "ghcr.io/letsinferlabs/engine@sha256:{}",
                "a".repeat(64)
            ))
            .expect("image"),
            Sha256Digest::parse(&"b".repeat(64)).expect("image identity"),
            docker_command(placement),
            LinuxContainerReadiness::endpoint(3, Duration::from_millis(1)).expect("readiness"),
            Some(endpoint(placement)),
        )
        .expect("Linux plan"),
    )
}

// Returns one verifier-only Linux plan bound to its exact local config identity.
fn local_config_linux_plan(placement: &Placement) -> ResolvedPlacementLaunchPlan {
    let image_id = Sha256Digest::parse(&"b".repeat(64)).expect("image identity");
    ResolvedPlacementLaunchPlan::Linux(
        LinuxContainerLaunchPlan::new(
            placement,
            RuntimeExecutionImageReference::local_config(image_id.clone()),
            image_id,
            docker_command_for_image(placement, format!("sha256:{}", "b".repeat(64))),
            LinuxContainerReadiness::endpoint(3, Duration::from_millis(1)).expect("readiness"),
            Some(endpoint(placement)),
        )
        .expect("local config Linux plan"),
    )
}

// Returns one complete macOS launch plan fixture.
fn macos_plan(placement: &Placement) -> ResolvedPlacementLaunchPlan {
    let command = ShellFreeCommand::new(
        PathBuf::from("/usr/bin/printf"),
        vec!["serve".to_string()],
        vec![ShellFreeEnvironmentValue::runtime("RUNTIME_MODE", "native").expect("runtime")],
        vec![
            ShellFreeEnvironmentValue::protected("LETSINFER_API_KEY_FILE", "/private/engine.key")
                .expect("credential file"),
            ShellFreeEnvironmentValue::protected("LETSINFER_TLS_CERT_FILE", "/private/engine.crt")
                .expect("certificate file"),
            ShellFreeEnvironmentValue::protected(
                "LETSINFER_TLS_KEY_FILE",
                "/private/engine-tls.key",
            )
            .expect("private key file"),
            ShellFreeEnvironmentValue::protected(
                "LETSINFER_CREDENTIAL_BUNDLE_SHA256",
                &"8".repeat(64),
            )
            .expect("bundle digest"),
        ],
        PathBuf::from("/tmp"),
    )
    .expect("command");
    ResolvedPlacementLaunchPlan::Macos(
        MacosLaunchAgentPlan::new(
            placement,
            command,
            Sha256Digest::parse(&"9".repeat(64)).expect("executable"),
            Some(endpoint(placement)),
            3,
            Duration::from_millis(1),
        )
        .expect("macOS plan"),
    )
}

// Mocks runtime-specific plan resolution and optional race synchronization.
struct MockResolver {
    value: ResolvedPlacementLaunchPlan,
    fail: AtomicBool,
    calls: AtomicUsize,
    barrier: Option<Arc<Barrier>>,
}

impl MockResolver {
    // Creates one deterministic resolver for an exact plan.
    fn new(value: ResolvedPlacementLaunchPlan) -> Self {
        Self {
            value,
            fail: AtomicBool::new(false),
            calls: AtomicUsize::new(0),
            barrier: None,
        }
    }

    // Creates one resolver that synchronizes exactly two concurrent calls.
    fn with_barrier(value: ResolvedPlacementLaunchPlan, barrier: Arc<Barrier>) -> Self {
        Self {
            value,
            fail: AtomicBool::new(false),
            calls: AtomicUsize::new(0),
            barrier: Some(barrier),
        }
    }
}

impl PlacementLaunchPlanResolver for MockResolver {
    // Returns the exact configured plan or resolver failure.
    fn resolve(
        &self,
        placement: &Placement,
        credentials: &PlacementCredentialReferences,
    ) -> Result<ResolvedPlacementLaunchPlan, PlacementError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(barrier) = &self.barrier {
            barrier.wait();
        }
        if self.fail.load(Ordering::SeqCst) {
            Err(PlacementError::ExecutionUnavailable)
        } else if credentials != &credential_references(placement) {
            Err(PlacementError::InvalidRequest {
                reason: "unexpected credential references",
            })
        } else {
            Ok(self.value.clone())
        }
    }
}

// Supplies deterministic unique private incoming identities.
struct MockIdentity {
    values: Mutex<VecDeque<String>>,
    fail: AtomicBool,
}

impl MockIdentity {
    // Creates one deterministic identity queue.
    fn new(values: &[char]) -> Self {
        Self {
            values: Mutex::new(
                values
                    .iter()
                    .map(|value| value.to_string().repeat(32))
                    .collect(),
            ),
            fail: AtomicBool::new(false),
        }
    }
}

impl PlacementMaterialIdentityProvider for MockIdentity {
    // Returns the next deterministic identity or entropy failure.
    fn identity(&self) -> Result<String, PlacementError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(PlacementError::ExecutionUnavailable);
        }
        self.values
            .lock()
            .expect("identities")
            .pop_front()
            .ok_or(PlacementError::ExecutionUnavailable)
    }
}

// Supplies one independently durable expected plan identity.
struct MockPlanIdentity {
    value: Option<Sha256Digest>,
    fail: AtomicBool,
}

impl MockPlanIdentity {
    // Creates one expected identity from an exact resolved plan.
    fn new(plan: &ResolvedPlacementLaunchPlan, placement: &Placement) -> Self {
        Self {
            value: Some(plan.identity(placement).expect("plan identity")),
            fail: AtomicBool::new(false),
        }
    }

    // Creates one identity source representing the initial pre-stage aggregate.
    fn absent() -> Self {
        Self {
            value: None,
            fail: AtomicBool::new(false),
        }
    }
}

impl PlacementLaunchPlanIdentityProvider for MockPlanIdentity {
    // Returns the configured durable identity or state failure.
    fn expected_identity(
        &self,
        _placement: &Placement,
    ) -> Result<Option<Sha256Digest>, PlacementError> {
        if self.fail.load(Ordering::SeqCst) {
            Err(PlacementError::ExecutionUnavailable)
        } else {
            Ok(self.value.clone())
        }
    }
}

// Mocks atomic reference-only credential provisioning for plan staging.
struct MockCredentials {
    references: PlacementCredentialReferences,
    provisioned: AtomicBool,
    failures: Mutex<HashSet<String>>,
    removed: AtomicUsize,
}

impl MockCredentials {
    // Creates one unprovisioned credential owner for the fixture placement.
    fn new(placement: &Placement) -> Self {
        Self {
            references: credential_references(placement),
            provisioned: AtomicBool::new(false),
            failures: Mutex::new(HashSet::new()),
            removed: AtomicUsize::new(0),
        }
    }

    // Configures one exact credential boundary to fail.
    fn fail(&self, action: &str) {
        self.failures
            .lock()
            .expect("failures")
            .insert(action.to_string());
    }

    // Returns whether one credential boundary must fail.
    fn should_fail(&self, action: &str) -> bool {
        self.failures.lock().expect("failures").contains(action)
    }
}

impl PlacementCredentialProvider for MockCredentials {
    // Creates or replays one exact reference set.
    fn provision(
        &self,
        _placement: &Placement,
    ) -> Result<PlacementCredentialProvision, PlacementError> {
        if self.should_fail("provision") {
            return Err(PlacementError::ExecutionUnavailable);
        }
        let created = !self.provisioned.swap(true, Ordering::SeqCst);
        Ok(PlacementCredentialProvision::new(
            self.references.clone(),
            if created {
                PlacementCredentialDisposition::Created
            } else {
                PlacementCredentialDisposition::Existing
            },
        ))
    }

    // Returns verified references when provisioned.
    fn existing(
        &self,
        _placement: &Placement,
    ) -> Result<Option<PlacementCredentialReferences>, PlacementError> {
        if self.should_fail("existing") {
            return Err(PlacementError::ExecutionUnavailable);
        }
        Ok(self
            .provisioned
            .load(Ordering::SeqCst)
            .then(|| self.references.clone()))
    }

    // Removes only exact matching references.
    fn remove_if_matches(
        &self,
        _placement: &Placement,
        references: &PlacementCredentialReferences,
    ) -> Result<bool, PlacementError> {
        if self.should_fail("remove_credentials") {
            return Err(PlacementError::ExecutionUnavailable);
        }
        if references != &self.references {
            return Err(PlacementError::StoreConflict);
        }
        let removed = self.provisioned.swap(false, Ordering::SeqCst);
        if removed {
            self.removed.fetch_add(1, Ordering::SeqCst);
        }
        Ok(removed)
    }
}

// Mocks private material filesystem state and atomic directory activation.
#[derive(Default)]
struct MockIo {
    directories: Mutex<HashSet<PathBuf>>,
    files: Mutex<HashMap<PathBuf, Vec<u8>>>,
    failures: Mutex<HashSet<String>>,
}

impl MockIo {
    // Configures one exact filesystem boundary to fail.
    fn fail(&self, action: &str) {
        self.failures
            .lock()
            .expect("failures")
            .insert(action.to_string());
    }

    // Returns whether one configured filesystem boundary must fail.
    fn should_fail(&self, action: &str) -> bool {
        self.failures.lock().expect("failures").contains(action)
    }

    // Inserts one exact private file for corruption fixtures.
    fn insert(&self, path: PathBuf, payload: Vec<u8>) {
        if let Some(parent) = path.parent() {
            self.directories
                .lock()
                .expect("directories")
                .insert(parent.to_path_buf());
        }
        self.files.lock().expect("files").insert(path, payload);
    }
}

impl PlacementMaterialIo for MockIo {
    // Creates one deterministic private directory or configured failure.
    fn ensure_private_directory(
        &self,
        path: &Path,
        _owner_user_id: u32,
    ) -> Result<(), PlacementError> {
        if self.should_fail("ensure") {
            return Err(PlacementError::ExecutionUnavailable);
        }
        self.directories
            .lock()
            .expect("directories")
            .insert(path.to_path_buf());
        Ok(())
    }

    // Creates one exact private file or configured failure.
    fn write_private_file(
        &self,
        path: &Path,
        payload: &[u8],
        _owner_user_id: u32,
    ) -> Result<(), PlacementError> {
        if self.should_fail("write") {
            return Err(PlacementError::ExecutionUnavailable);
        }
        let mut files = self.files.lock().expect("files");
        if files.contains_key(path) {
            return Err(PlacementError::ExecutionUnavailable);
        }
        files.insert(path.to_path_buf(), payload.to_vec());
        Ok(())
    }

    // Returns one bounded private file or configured read failure.
    fn read_private_file(
        &self,
        path: &Path,
        maximum_bytes: usize,
        _owner_user_id: u32,
    ) -> Result<Option<Vec<u8>>, PlacementError> {
        if self.should_fail("read") {
            return Err(PlacementError::ExecutionUnavailable);
        }
        let value = self.files.lock().expect("files").get(path).cloned();
        if value
            .as_ref()
            .is_some_and(|payload| payload.len() > maximum_bytes)
        {
            return Err(PlacementError::ExecutionUnavailable);
        }
        Ok(value)
    }

    // Atomically moves one directory and every direct file under one lock.
    fn rename_private_directory(
        &self,
        source: &Path,
        destination: &Path,
        _owner_user_id: u32,
    ) -> Result<(), PlacementError> {
        if self.should_fail("rename") {
            return Err(PlacementError::ExecutionUnavailable);
        }
        let mut directories = self.directories.lock().expect("directories");
        if !directories.contains(source) || directories.contains(destination) {
            return Err(PlacementError::ExecutionUnavailable);
        }
        let mut files = self.files.lock().expect("files");
        let moved = files
            .iter()
            .filter(|(path, _)| path.parent() == Some(source))
            .map(|(path, payload)| {
                (
                    destination.join(path.file_name().expect("file name")),
                    payload.clone(),
                )
            })
            .collect::<Vec<_>>();
        let old = files
            .keys()
            .filter(|path| path.parent() == Some(source))
            .cloned()
            .collect::<Vec<_>>();
        for path in old {
            files.remove(&path);
        }
        for (path, payload) in moved {
            files.insert(path, payload);
        }
        directories.remove(source);
        directories.insert(destination.to_path_buf());
        Ok(())
    }

    // Removes one exact directory only when every file name is known.
    fn remove_material_directory(
        &self,
        path: &Path,
        _owner_user_id: u32,
    ) -> Result<bool, PlacementError> {
        if self.should_fail("remove") {
            return Err(PlacementError::ExecutionUnavailable);
        }
        let mut directories = self.directories.lock().expect("directories");
        if !directories.contains(path) {
            return Ok(false);
        }
        let mut files = self.files.lock().expect("files");
        let entries = files
            .keys()
            .filter(|candidate| candidate.parent() == Some(path))
            .cloned()
            .collect::<Vec<_>>();
        if entries.iter().any(|entry| {
            !matches!(
                entry.file_name().and_then(|value| value.to_str()),
                Some(PLAN_FILE | DIGEST_FILE)
            )
        }) {
            return Err(PlacementError::ExecutionUnavailable);
        }
        for entry in entries {
            files.remove(&entry);
        }
        directories.remove(path);
        Ok(true)
    }

    // Lists direct child names or configured listing failure.
    fn entries(&self, path: &Path, _owner_user_id: u32) -> Result<Vec<String>, PlacementError> {
        if self.should_fail("entries") {
            return Err(PlacementError::ExecutionUnavailable);
        }
        let directories = self.directories.lock().expect("directories");
        let mut values = directories
            .iter()
            .filter(|candidate| candidate.parent() == Some(path))
            .filter_map(|candidate| candidate.file_name()?.to_str().map(str::to_string))
            .collect::<Vec<_>>();
        values.sort();
        Ok(values)
    }
}

// Groups one provider and its retained deterministic boundaries.
struct Fixture {
    provider: Arc<FilesystemPlacementMaterialProvider>,
    io: Arc<MockIo>,
    resolver: Arc<MockResolver>,
    identities: Arc<MockIdentity>,
    plan_identity: Arc<MockPlanIdentity>,
    credentials: Arc<MockCredentials>,
    placement: Placement,
    root: PathBuf,
}

// Creates one Linux or macOS material fixture.
fn fixture(macos: bool) -> Fixture {
    let placement = placement(true);
    let resolved = if macos {
        macos_plan(&placement)
    } else {
        linux_plan(&placement)
    };
    let resolver = Arc::new(MockResolver::new(resolved.clone()));
    let io = Arc::new(MockIo::default());
    let identities = Arc::new(MockIdentity::new(&['8', '9']));
    let plan_identity = Arc::new(MockPlanIdentity::new(&resolved, &placement));
    let credentials = Arc::new(MockCredentials::new(&placement));
    let root = PathBuf::from("/managed/placement_material");
    let provider = Arc::new(
        FilesystemPlacementMaterialProvider::new(
            root.clone(),
            501,
            io.clone(),
            resolver.clone(),
            identities.clone(),
            plan_identity.clone(),
            credentials.clone(),
        )
        .expect("provider"),
    );
    Fixture {
        provider,
        io,
        resolver,
        identities,
        plan_identity,
        credentials,
        placement,
        root,
    }
}

// Returns the exact final directory for one fixture placement.
fn destination(fixture: &Fixture) -> PathBuf {
    fixture.root.join(fixture.placement.placement_id().as_str())
}

// Returns one lowercase SHA-256 digest for corruption fixtures.
fn digest(payload: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(payload);
    format!("{:x}", digest.finalize())
}

// Rejects plaintext secret arguments, environment fields, and bearer-shaped values.
#[test]
fn durable_plan_audit_rejects_every_secret_shape() {
    let placement = placement(true);
    for command in [
        ShellFreeCommand::new(
            PathBuf::from("/usr/bin/printf"),
            vec!["--api-key".to_string(), "plaintext".to_string()],
            Vec::new(),
            Vec::new(),
            PathBuf::from("/tmp"),
        )
        .expect("command"),
        ShellFreeCommand::new(
            PathBuf::from("/usr/bin/printf"),
            Vec::new(),
            vec![ShellFreeEnvironmentValue::runtime("AUTH_TOKEN", "plaintext").expect("token")],
            Vec::new(),
            PathBuf::from("/tmp"),
        )
        .expect("command"),
        ShellFreeCommand::new(
            PathBuf::from("/usr/bin/printf"),
            Vec::new(),
            vec![ShellFreeEnvironmentValue::runtime(
                "HF_TOKEN",
                "hf_abcdefghijklmnopqrstuvwxyz123456",
            )
            .expect("token")],
            Vec::new(),
            PathBuf::from("/tmp"),
        )
        .expect("command"),
        ShellFreeCommand::new(
            PathBuf::from("/usr/bin/printf"),
            Vec::new(),
            vec![ShellFreeEnvironmentValue::runtime(
                "MODEL_REFERENCE",
                &format!("li_{}_{}", "1".repeat(32), "2".repeat(64)),
            )
            .expect("bearer")],
            Vec::new(),
            PathBuf::from("/tmp"),
        )
        .expect("command"),
    ] {
        let resolved = ResolvedPlacementLaunchPlan::Macos(
            MacosLaunchAgentPlan::new(
                &placement,
                command,
                Sha256Digest::parse(&"9".repeat(64)).expect("executable"),
                Some(endpoint(&placement)),
                1,
                Duration::from_millis(1),
            )
            .expect("plan"),
        );
        assert!(resolved.validate_for(&placement).is_err());
    }
    assert!(macos_plan(&placement).validate_for(&placement).is_ok());
    let reference = ResolvedPlacementLaunchPlan::Macos(
        MacosLaunchAgentPlan::new(
            &placement,
            ShellFreeCommand::new(
                PathBuf::from("/usr/bin/printf"),
                Vec::new(),
                vec![ShellFreeEnvironmentValue::runtime(
                    "MODEL_PASSWORD_FILE",
                    "/private/password",
                )
                .expect("reference")],
                Vec::new(),
                PathBuf::from("/tmp"),
            )
            .expect("command"),
            Sha256Digest::parse(&"9".repeat(64)).expect("executable"),
            Some(endpoint(&placement)),
            1,
            Duration::from_millis(1),
        )
        .expect("plan"),
    );
    assert!(reference.validate_for(&placement).is_ok());
}

// Rejects noncanonical roots and cross-platform plan projection.
#[test]
fn material_provider_rejects_invalid_root_and_platform_projection() {
    let placement = placement(true);
    let resolved = linux_plan(&placement);
    for root in [
        PathBuf::from("relative/placement_material"),
        PathBuf::from("/managed/wrong"),
    ] {
        assert!(FilesystemPlacementMaterialProvider::new(
            root,
            501,
            Arc::new(MockIo::default()),
            Arc::new(MockResolver::new(resolved.clone())),
            Arc::new(MockIdentity::new(&['8'])),
            Arc::new(MockPlanIdentity::new(&resolved, &placement)),
            Arc::new(MockCredentials::new(&placement)),
        )
        .is_err());
    }

    let macos = fixture(true);
    MacosPlacementMaterialProvider::stage(macos.provider.as_ref(), &macos.placement)
        .expect("stage macOS");
    assert!(
        LinuxPlacementMaterialProvider::plan(macos.provider.as_ref(), &macos.placement).is_err()
    );
    let linux = fixture(false);
    LinuxPlacementMaterialProvider::stage(linux.provider.as_ref(), &linux.placement)
        .expect("stage Linux");
    assert!(
        MacosPlacementMaterialProvider::plan(linux.provider.as_ref(), &linux.placement).is_err()
    );
}

// Stages and reconstructs complete Linux and macOS plans across provider restart.
#[test]
fn material_store_round_trips_both_platform_plans() {
    for macos in [false, true] {
        let fixture = fixture(macos);
        if macos {
            MacosPlacementMaterialProvider::stage(fixture.provider.as_ref(), &fixture.placement)
                .expect("stage macOS");
            let observed =
                MacosPlacementMaterialProvider::plan(fixture.provider.as_ref(), &fixture.placement)
                    .expect("plan")
                    .expect("stored plan");
            assert_eq!(
                ResolvedPlacementLaunchPlan::Macos(observed),
                fixture.resolver.value
            );
        } else {
            LinuxPlacementMaterialProvider::stage(fixture.provider.as_ref(), &fixture.placement)
                .expect("stage Linux");
            let observed =
                LinuxPlacementMaterialProvider::plan(fixture.provider.as_ref(), &fixture.placement)
                    .expect("plan")
                    .expect("stored plan");
            assert_eq!(
                ResolvedPlacementLaunchPlan::Linux(observed),
                fixture.resolver.value
            );
        }
        assert_eq!(fixture.resolver.calls.load(Ordering::SeqCst), 1);
        let bytes = fixture
            .io
            .files
            .lock()
            .expect("files")
            .values()
            .flatten()
            .copied()
            .collect::<Vec<_>>();
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains("plaintext"));
        assert!(!text.contains(concat!("PRIVATE", " KEY")));
    }
}

// Binds a read to one already-observed plan generation without consulting mutable state again.
#[test]
fn material_reader_uses_the_callers_exact_snapshot_identity() {
    let fixture = fixture(true);
    MacosPlacementMaterialProvider::stage(fixture.provider.as_ref(), &fixture.placement)
        .expect("stage macOS");
    let expected = fixture
        .resolver
        .value
        .identity(&fixture.placement)
        .expect("identity");
    fixture.plan_identity.fail.store(true, Ordering::SeqCst);
    let reader = FilesystemPlacementMaterialReader::new(
        fixture.root,
        501,
        fixture.io,
        fixture.plan_identity,
    )
    .expect("reader");
    assert!(reader.macos_plan(&fixture.placement).is_err());
    assert!(reader
        .macos_plan_with_expected_identity(&fixture.placement, &expected)
        .expect("snapshot plan")
        .is_some());
    assert!(reader
        .macos_plan_with_expected_identity(
            &fixture.placement,
            &Sha256Digest::parse(&"f".repeat(64)).expect("foreign identity"),
        )
        .is_err());
}

// Reconstructs an installation-bound local config without widening it into a mutable tag.
#[test]
fn material_store_round_trips_local_config_execution_identity() {
    let placement = placement(true);
    let resolved = local_config_linux_plan(&placement);
    let io = Arc::new(MockIo::default());
    let provider = FilesystemPlacementMaterialProvider::new(
        PathBuf::from("/managed/placement_material"),
        501,
        io,
        Arc::new(MockResolver::new(resolved.clone())),
        Arc::new(MockIdentity::new(&['8'])),
        Arc::new(MockPlanIdentity::new(&resolved, &placement)),
        Arc::new(MockCredentials::new(&placement)),
    )
    .expect("provider");
    LinuxPlacementMaterialProvider::stage(&provider, &placement).expect("stage local config");
    let observed = LinuxPlacementMaterialProvider::plan(&provider, &placement)
        .expect("read local config")
        .expect("stored plan");
    assert_eq!(
        observed.image_reference().as_str(),
        format!("sha256:{}", "b".repeat(64))
    );
    assert_eq!(
        observed.image_reference().local_config_digest(),
        Some(observed.image_id())
    );
    assert_eq!(ResolvedPlacementLaunchPlan::Linux(observed), resolved);
}

// Initial staging returns the resolved identity before the aggregate commits it.
#[test]
fn material_stage_supports_initial_absent_durable_identity() {
    let placement = placement(true);
    let resolved = linux_plan(&placement);
    let provider = FilesystemPlacementMaterialProvider::new(
        PathBuf::from("/managed/placement_material"),
        501,
        Arc::new(MockIo::default()),
        Arc::new(MockResolver::new(resolved.clone())),
        Arc::new(MockIdentity::new(&['8'])),
        Arc::new(MockPlanIdentity::absent()),
        Arc::new(MockCredentials::new(&placement)),
    )
    .expect("provider");
    assert_eq!(
        LinuxPlacementMaterialProvider::stage(&provider, &placement).expect("initial stage"),
        resolved.identity(&placement).expect("identity")
    );
}

// Replays staged material without resolving or rewriting the immutable plan.
#[test]
fn material_stage_is_idempotent_after_restart() {
    for macos in [false, true] {
        let fixture = fixture(macos);
        if macos {
            MacosPlacementMaterialProvider::stage(fixture.provider.as_ref(), &fixture.placement)
                .expect("first stage");
        } else {
            LinuxPlacementMaterialProvider::stage(fixture.provider.as_ref(), &fixture.placement)
                .expect("first stage");
        }
        let before = fixture.io.files.lock().expect("files").clone();
        if macos {
            MacosPlacementMaterialProvider::stage(fixture.provider.as_ref(), &fixture.placement)
                .expect("replayed stage");
        } else {
            LinuxPlacementMaterialProvider::stage(fixture.provider.as_ref(), &fixture.placement)
                .expect("replayed stage");
        }
        assert_eq!(fixture.resolver.calls.load(Ordering::SeqCst), 1);
        assert_eq!(*fixture.io.files.lock().expect("files"), before);
    }
}

// Refuses to replay a durable plan when its referenced secret directory is missing.
#[test]
fn material_replay_requires_verified_credential_references() {
    let fixture = fixture(false);
    LinuxPlacementMaterialProvider::stage(fixture.provider.as_ref(), &fixture.placement)
        .expect("stage");
    fixture
        .credentials
        .provisioned
        .store(false, Ordering::SeqCst);
    assert!(
        LinuxPlacementMaterialProvider::stage(fixture.provider.as_ref(), &fixture.placement,)
            .is_err()
    );
    fixture
        .credentials
        .provisioned
        .store(true, Ordering::SeqCst);
    fixture.credentials.fail("existing");
    assert!(
        LinuxPlacementMaterialProvider::plan(fixture.provider.as_ref(), &fixture.placement,)
            .is_ok()
    );
    assert!(
        LinuxPlacementMaterialProvider::stage(fixture.provider.as_ref(), &fixture.placement,)
            .is_err()
    );
}

// Rejects changed bytes, digest, partial records, and semantically corrupt signed JSON.
#[test]
fn material_read_fails_closed_on_every_corruption_shape() {
    for corruption in ["bytes", "digest", "partial", "semantic"] {
        let fixture = fixture(false);
        LinuxPlacementMaterialProvider::stage(fixture.provider.as_ref(), &fixture.placement)
            .expect("stage");
        let root = destination(&fixture);
        let plan_path = root.join(PLAN_FILE);
        let digest_path = root.join(DIGEST_FILE);
        match corruption {
            "bytes" => fixture.io.insert(plan_path, b"changed\n".to_vec()),
            "digest" => fixture
                .io
                .insert(digest_path, format!("{}\n", "0".repeat(64)).into_bytes()),
            "partial" => {
                fixture.io.files.lock().expect("files").remove(&digest_path);
            }
            _ => {
                let original = fixture
                    .io
                    .files
                    .lock()
                    .expect("files")
                    .get(&plan_path)
                    .expect("plan")
                    .clone();
                let changed = String::from_utf8(original)
                    .expect("UTF-8")
                    .replacen("\"platform\":\"linux\"", "\"platform\":\"foreign\"", 1)
                    .into_bytes();
                fixture.io.insert(plan_path, changed.clone());
                fixture
                    .io
                    .insert(digest_path, format!("{}\n", digest(&changed)).into_bytes());
            }
        }
        assert!(
            LinuxPlacementMaterialProvider::plan(fixture.provider.as_ref(), &fixture.placement,)
                .is_err(),
            "{corruption}"
        );
    }
}

// Cleans exact incoming material after resolver, identity, write, read, or rename failure.
#[test]
fn material_stage_rolls_back_every_external_failure() {
    for boundary in [
        "resolver",
        "credentials",
        "identity",
        "plan_identity",
        "ensure",
        "write",
        "read",
        "rename",
    ] {
        let fixture = fixture(false);
        match boundary {
            "resolver" => fixture.resolver.fail.store(true, Ordering::SeqCst),
            "credentials" => fixture.credentials.fail("provision"),
            "identity" => fixture.identities.fail.store(true, Ordering::SeqCst),
            "plan_identity" => fixture.plan_identity.fail.store(true, Ordering::SeqCst),
            value => fixture.io.fail(value),
        }
        assert!(
            LinuxPlacementMaterialProvider::stage(fixture.provider.as_ref(), &fixture.placement,)
                .is_err(),
            "{boundary}"
        );
        assert!(!fixture
            .io
            .directories
            .lock()
            .expect("directories")
            .iter()
            .any(|path| path
                .file_name()
                .and_then(|value| value.to_str())
                .is_some_and(|value| value.contains(".incoming."))));
        if matches!(
            boundary,
            "resolver" | "identity" | "plan_identity" | "write" | "rename"
        ) {
            assert_eq!(fixture.credentials.removed.load(Ordering::SeqCst), 1);
        }
    }
}

// Allows one identical concurrent winner and rejects divergent immutable resolution.
#[test]
fn material_stage_resolves_concurrent_races_atomically() {
    let placement = placement(true);
    let root = PathBuf::from("/managed/placement_material");
    let io = Arc::new(MockIo::default());
    let credentials = Arc::new(MockCredentials::new(&placement));
    let barrier = Arc::new(Barrier::new(2));
    let first = Arc::new(
        FilesystemPlacementMaterialProvider::new(
            root.clone(),
            501,
            io.clone(),
            Arc::new(MockResolver::with_barrier(
                linux_plan(&placement),
                barrier.clone(),
            )),
            Arc::new(MockIdentity::new(&['8'])),
            Arc::new(MockPlanIdentity::new(&linux_plan(&placement), &placement)),
            credentials.clone(),
        )
        .expect("first"),
    );
    let second = Arc::new(
        FilesystemPlacementMaterialProvider::new(
            root.clone(),
            501,
            io.clone(),
            Arc::new(MockResolver::with_barrier(linux_plan(&placement), barrier)),
            Arc::new(MockIdentity::new(&['9'])),
            Arc::new(MockPlanIdentity::new(&linux_plan(&placement), &placement)),
            credentials,
        )
        .expect("second"),
    );
    let (first_result, second_result) = std::thread::scope(|scope| {
        let first =
            scope.spawn(|| LinuxPlacementMaterialProvider::stage(first.as_ref(), &placement));
        let second =
            scope.spawn(|| LinuxPlacementMaterialProvider::stage(second.as_ref(), &placement));
        (
            first.join().expect("first thread"),
            second.join().expect("second thread"),
        )
    });
    assert!(first_result.is_ok());
    assert!(second_result.is_ok());
    assert!(io
        .directories
        .lock()
        .expect("directories")
        .contains(&root.join(placement.placement_id().as_str())));

    let divergent_io = Arc::new(MockIo::default());
    let divergent_credentials = Arc::new(MockCredentials::new(&placement));
    let barrier = Arc::new(Barrier::new(2));
    let linux = Arc::new(
        FilesystemPlacementMaterialProvider::new(
            root.clone(),
            501,
            divergent_io.clone(),
            Arc::new(MockResolver::with_barrier(
                linux_plan(&placement),
                barrier.clone(),
            )),
            Arc::new(MockIdentity::new(&['a'])),
            Arc::new(MockPlanIdentity::new(&linux_plan(&placement), &placement)),
            divergent_credentials.clone(),
        )
        .expect("Linux"),
    );
    let macos = Arc::new(
        FilesystemPlacementMaterialProvider::new(
            root,
            501,
            divergent_io,
            Arc::new(MockResolver::with_barrier(macos_plan(&placement), barrier)),
            Arc::new(MockIdentity::new(&['b'])),
            Arc::new(MockPlanIdentity::new(&macos_plan(&placement), &placement)),
            divergent_credentials,
        )
        .expect("macOS"),
    );
    let (linux_result, macos_result) = std::thread::scope(|scope| {
        let linux =
            scope.spawn(|| LinuxPlacementMaterialProvider::stage(linux.as_ref(), &placement));
        let macos =
            scope.spawn(|| MacosPlacementMaterialProvider::stage(macos.as_ref(), &placement));
        (
            linux.join().expect("Linux thread"),
            macos.join().expect("macOS thread"),
        )
    });
    assert_eq!(
        usize::from(linux_result.is_ok()) + usize::from(macos_result.is_ok()),
        1
    );
}

// Removes final and stale incoming material while rejecting unknown contents.
#[test]
fn material_remove_is_exact_idempotent_and_fail_closed() {
    let completed = fixture(false);
    LinuxPlacementMaterialProvider::stage(completed.provider.as_ref(), &completed.placement)
        .expect("stage");
    let stale = completed.root.join(format!(
        ".{}.incoming.{}",
        completed.placement.placement_id().as_str(),
        "a".repeat(32)
    ));
    completed
        .io
        .directories
        .lock()
        .expect("directories")
        .insert(stale.clone());
    completed
        .io
        .insert(stale.join(PLAN_FILE), b"stale".to_vec());
    LinuxPlacementMaterialProvider::remove(completed.provider.as_ref(), &completed.placement)
        .expect("remove");
    LinuxPlacementMaterialProvider::remove(completed.provider.as_ref(), &completed.placement)
        .expect("replayed remove");
    assert!(!completed
        .io
        .directories
        .lock()
        .expect("directories")
        .contains(&destination(&completed)));
    assert_eq!(completed.credentials.removed.load(Ordering::SeqCst), 1);

    let unsafe_fixture = fixture(false);
    LinuxPlacementMaterialProvider::stage(
        unsafe_fixture.provider.as_ref(),
        &unsafe_fixture.placement,
    )
    .expect("stage");
    unsafe_fixture.io.insert(
        destination(&unsafe_fixture).join("foreign"),
        b"data".to_vec(),
    );
    assert!(LinuxPlacementMaterialProvider::remove(
        unsafe_fixture.provider.as_ref(),
        &unsafe_fixture.placement,
    )
    .is_err());

    for boundary in ["entries", "remove"] {
        let fixture = fixture(false);
        LinuxPlacementMaterialProvider::stage(fixture.provider.as_ref(), &fixture.placement)
            .expect("stage");
        fixture.io.fail(boundary);
        assert!(
            LinuxPlacementMaterialProvider::remove(fixture.provider.as_ref(), &fixture.placement,)
                .is_err(),
            "{boundary}"
        );
    }

    let credential_failure = fixture(false);
    LinuxPlacementMaterialProvider::stage(
        credential_failure.provider.as_ref(),
        &credential_failure.placement,
    )
    .expect("stage");
    credential_failure.credentials.fail("remove_credentials");
    assert!(LinuxPlacementMaterialProvider::remove(
        credential_failure.provider.as_ref(),
        &credential_failure.placement,
    )
    .is_err());
    credential_failure
        .credentials
        .failures
        .lock()
        .expect("failures")
        .clear();
    LinuxPlacementMaterialProvider::remove(
        credential_failure.provider.as_ref(),
        &credential_failure.placement,
    )
    .expect("credential cleanup retry");
}

// Rejects a resolver plan whose immutable placement identity differs.
#[test]
fn material_stage_rejects_resolver_identity_mismatch() {
    let placement = placement(true);
    let mut foreign = placement.clone();
    foreign = Placement::new(
        PlacementId::parse(&"9".repeat(32)).expect("foreign"),
        foreign.placement_group_id().clone(),
        foreign.assignment().clone(),
        foreign.state(),
        None,
        None,
        foreign.timestamps(),
    )
    .expect("foreign placement");
    let io = Arc::new(MockIo::default());
    let provider = FilesystemPlacementMaterialProvider::new(
        PathBuf::from("/managed/placement_material"),
        501,
        io.clone(),
        Arc::new(MockResolver::new(linux_plan(&foreign))),
        Arc::new(MockIdentity::new(&['8'])),
        Arc::new(MockPlanIdentity::new(&linux_plan(&foreign), &foreign)),
        Arc::new(MockCredentials::new(&placement)),
    )
    .expect("provider");
    assert!(LinuxPlacementMaterialProvider::stage(&provider, &placement).is_err());
    assert!(!io
        .directories
        .lock()
        .expect("directories")
        .iter()
        .any(|path| path
            .file_name()
            .and_then(|value| value.to_str())
            .is_some_and(|value| value.contains(".incoming."))));
}

// System material I/O enforces private modes, no-follow files, known contents, and atomic rename.
#[test]
fn system_material_io_enforces_private_filesystem_contract() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let owner = fs::metadata(directory.path()).expect("metadata").uid();
    let root = directory.path().join("placement_material");
    let incoming = root.join(format!(".{}.incoming.{}", "1".repeat(32), "8".repeat(32)));
    let destination = root.join("1".repeat(32));
    let io = SystemPlacementMaterialIo;
    io.ensure_private_directory(&root, owner).expect("root");
    io.ensure_private_directory(&incoming, owner)
        .expect("incoming");
    io.write_private_file(&incoming.join(PLAN_FILE), b"plan\n", owner)
        .expect("plan");
    io.write_private_file(
        &incoming.join(DIGEST_FILE),
        format!("{}\n", "0".repeat(64)).as_bytes(),
        owner,
    )
    .expect("digest");
    io.rename_private_directory(&incoming, &destination, owner)
        .expect("rename");
    assert_eq!(
        fs::metadata(&destination)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let plan_path = destination.join(PLAN_FILE);
    assert_eq!(
        fs::metadata(&plan_path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let link = destination.join("link");
    std::os::unix::fs::symlink(&plan_path, &link).expect("symlink");
    assert!(io.read_private_file(&link, 32, owner).is_err());
    fs::remove_file(&link).expect("remove link");
    fs::set_permissions(&plan_path, fs::Permissions::from_mode(0o644)).expect("permissions");
    assert!(io.read_private_file(&plan_path, 32, owner).is_err());
    fs::set_permissions(&plan_path, fs::Permissions::from_mode(0o600)).expect("permissions");
    let foreign = destination.join("foreign");
    fs::write(&foreign, b"data").expect("foreign");
    fs::set_permissions(&foreign, fs::Permissions::from_mode(0o600)).expect("permissions");
    assert!(io.remove_material_directory(&destination, owner).is_err());
    fs::remove_file(&foreign).expect("remove foreign");
    assert!(io
        .remove_material_directory(&destination, owner)
        .expect("remove"));

    let public = root.join("public");
    fs::create_dir(&public).expect("public");
    fs::set_permissions(&public, fs::Permissions::from_mode(0o755)).expect("permissions");
    assert!(io.ensure_private_directory(&public, owner).is_err());
    let link = root.join("link");
    std::os::unix::fs::symlink(&public, &link).expect("directory symlink");
    assert!(io.ensure_private_directory(&link, owner).is_err());
}

// System material identities are canonical and nonrepeating.
#[test]
fn system_material_identity_is_canonical_and_nonrepeating() {
    let provider = SystemPlacementMaterialIdentityProvider;
    let first = provider.identity().expect("first");
    let second = provider.identity().expect("second");
    assert_eq!(first.len(), 32);
    assert_ne!(first, second);
}
