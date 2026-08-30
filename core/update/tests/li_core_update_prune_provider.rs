// SPDX-License-Identifier: AGPL-3.0-only

use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use li_core_interface::Sha256Digest;
use li_core_update_manager::{
    CoreInstallation, CoreUpdateArtifactIo, CoreUpdateError, CoreUpdatePathKind,
    CoreUpdatePruneEntry, CoreUpdatePruneIo, CoreUpdatePruneReferenceProvider,
    CoreUpdatePruneReferences, CoreVersion, FilesystemCoreUpdateArtifactIo,
    FilesystemCoreUpdatePruneIo, ReferenceAwareCoreUpdatePruneProvider,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const VERSION_DIRECTORY_MODE: u32 = 0o755;
const IMMUTABLE_DIRECTORY_MODE: u32 = 0o555;
const CORE_RELEASE_MANIFEST_NAME: &str = "li_core_release_manifest_v1.json";

// Returns one stable redacted mock-provider failure.
fn mock_error(reason: &'static str) -> CoreUpdateError {
    CoreUpdateError::provider("prune", reason)
}

// Parses one deterministic hexadecimal identity used by fixtures.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&character.to_string().repeat(64)).expect("digest")
}

// Hashes exact fixture bytes into one canonical identity.
fn digest_bytes(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::parse(&format!("{:x}", Sha256::digest(bytes))).expect("digest")
}

// Serializes one compact canonical JSON document with its required final newline.
fn canonical_json(value: &serde_json::Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(value).expect("JSON");
    bytes.push(b'\n');
    bytes
}

// Creates one directory and applies its exact expected protection.
fn create_directory(path: &Path, mode: u32) {
    fs::create_dir_all(path).expect("directory");
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("directory mode");
}

// Writes one exact file before applying its final immutable or private mode.
fn write_file(path: &Path, bytes: &[u8], mode: u32) {
    if let Some(parent) = path.parent() {
        create_directory(parent, PRIVATE_DIRECTORY_MODE);
    }
    fs::write(path, bytes).expect("file");
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("file mode");
}

// Restores writable fixture permissions so temporary roots clean up reliably.
fn make_tree_writable(root: &Path) {
    let Ok(metadata) = fs::symlink_metadata(root) else {
        return;
    };
    if metadata.file_type().is_symlink() {
        return;
    }
    if metadata.is_dir() {
        if let Ok(children) = fs::read_dir(root) {
            for child in children.flatten() {
                make_tree_writable(&child.path());
            }
        }
        let _ = fs::set_permissions(root, fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE));
    } else if metadata.is_file() {
        let _ = fs::set_permissions(root, fs::Permissions::from_mode(0o600));
    }
}

// Supplies one mutable deterministic reference snapshot or an injected failure.
struct ReferenceMock {
    references: Mutex<CoreUpdatePruneReferences>,
    should_fail: AtomicBool,
    calls: AtomicUsize,
}

impl ReferenceMock {
    // Creates one reference capability from an exact canonical snapshot.
    fn new(references: CoreUpdatePruneReferences) -> Self {
        Self {
            references: Mutex::new(references),
            should_fail: AtomicBool::new(false),
            calls: AtomicUsize::new(0),
        }
    }

    // Makes subsequent reads fail before any native mutation can begin.
    fn fail(&self) {
        self.should_fail.store(true, Ordering::SeqCst);
    }
}

impl CoreUpdatePruneReferenceProvider for ReferenceMock {
    // Returns one cloned consistent reference view or its deterministic failure.
    fn references(
        &self,
        _update_id: &Sha256Digest,
        _active: &CoreInstallation,
    ) -> Result<CoreUpdatePruneReferences, CoreUpdateError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.should_fail.load(Ordering::SeqCst) {
            return Err(mock_error("mock references unavailable"));
        }
        Ok(self.references.lock().expect("references").clone())
    }
}

// Wraps real no-follow I/O with deterministic removal observation and one-shot failure.
struct PruneIoMock {
    native: FilesystemCoreUpdatePruneIo,
    remove_calls: AtomicUsize,
    fail_remove_call: Mutex<Option<usize>>,
    removed: Mutex<Vec<PathBuf>>,
}

impl PruneIoMock {
    // Creates one mock around the same native implementation used in production.
    fn new(owner_user_id: u32) -> Self {
        Self {
            native: FilesystemCoreUpdatePruneIo::new(owner_user_id),
            remove_calls: AtomicUsize::new(0),
            fail_remove_call: Mutex::new(None),
            removed: Mutex::new(Vec::new()),
        }
    }

    // Fails one exact tree-removal boundary before that target mutates.
    fn fail_remove_call(&self, call: usize) {
        *self.fail_remove_call.lock().expect("failure") = Some(call);
    }

    // Returns the exact successfully removed roots in call order.
    fn removed(&self) -> Vec<PathBuf> {
        self.removed.lock().expect("removed").clone()
    }
}

impl CoreUpdatePruneIo for PruneIoMock {
    // Delegates no-follow final-path classification to native I/O.
    fn path_kind(&self, path: &Path) -> Result<CoreUpdatePathKind, CoreUpdateError> {
        self.native.path_kind(path)
    }

    // Delegates exact owner and directory-mode validation to native I/O.
    fn require_directory(&self, path: &Path, mode: u32) -> Result<(), CoreUpdateError> {
        self.native.require_directory(path, mode)
    }

    // Delegates deterministic immediate-child inventory to native I/O.
    fn directory_entries(&self, root: &Path) -> Result<Vec<CoreUpdatePruneEntry>, CoreUpdateError> {
        self.native.directory_entries(root)
    }

    // Delegates bounded recursive hashing inventory to native I/O.
    fn inventory(
        &self,
        root: &Path,
        maximum_entries: usize,
        maximum_bytes: u64,
    ) -> Result<Vec<CoreUpdatePruneEntry>, CoreUpdateError> {
        self.native.inventory(root, maximum_entries, maximum_bytes)
    }

    // Delegates bounded descriptor reads to native I/O.
    fn read_regular_file(
        &self,
        path: &Path,
        maximum_bytes: u64,
    ) -> Result<Vec<u8>, CoreUpdateError> {
        self.native.read_regular_file(path, maximum_bytes)
    }

    // Records successful exact removals and injects one selected boundary failure.
    fn remove_tree(
        &self,
        path: &Path,
        root_mode: u32,
        parent_mode: u32,
    ) -> Result<(), CoreUpdateError> {
        let call = self.remove_calls.fetch_add(1, Ordering::SeqCst) + 1;
        let mut failure = self.fail_remove_call.lock().expect("failure");
        if failure.is_some_and(|expected| expected == call) {
            *failure = None;
            return Err(mock_error("mock tree removal failed"));
        }
        drop(failure);
        self.native.remove_tree(path, root_mode, parent_mode)?;
        self.removed
            .lock()
            .expect("removed")
            .push(path.to_path_buf());
        Ok(())
    }

    // Records successful empty-version removal through the same native boundary.
    fn remove_empty_directory(
        &self,
        path: &Path,
        mode: u32,
        parent_mode: u32,
    ) -> Result<(), CoreUpdateError> {
        self.native
            .remove_empty_directory(path, mode, parent_mode)?;
        self.removed
            .lock()
            .expect("removed")
            .push(path.to_path_buf());
        Ok(())
    }
}

// Owns one complete filesystem and provider fixture for a prune lifecycle.
struct TestEnvironment {
    temporary: TempDir,
    home: PathBuf,
    active: CoreInstallation,
    recovery: CoreInstallation,
    stale: CoreInstallation,
    active_workspace: Sha256Digest,
    stale_workspace: Sha256Digest,
    references: Arc<ReferenceMock>,
    io: Arc<PruneIoMock>,
    provider: ReferenceAwareCoreUpdatePruneProvider,
}

impl TestEnvironment {
    // Creates active, recovery, stale, and workspace identities in one fixed layout.
    fn new() -> Self {
        let temporary = tempfile::tempdir().expect("temporary root");
        let home = temporary.path().join("letsinfer-home");
        create_directory(&home, PRIVATE_DIRECTORY_MODE);
        create_directory(&home.join("core"), PRIVATE_DIRECTORY_MODE);
        create_directory(&home.join("core/versions"), VERSION_DIRECTORY_MODE);
        create_directory(&home.join("core/staging"), PRIVATE_DIRECTORY_MODE);

        let active = create_core(&home, "1.2.0", b"active");
        let recovery = create_core(&home, "1.1.0", b"recovery");
        let stale = create_core(&home, "1.0.0", b"stale");
        symlink(core_path(&home, &active), home.join("core/current")).expect("current link");

        let active_workspace = digest('a');
        let stale_workspace = digest('b');
        create_workspace(&home, &active_workspace);
        create_workspace(&home, &stale_workspace);

        create_directory(&home.join("models/keep"), PRIVATE_DIRECTORY_MODE);
        write_file(&home.join("models/keep/model.bin"), b"model", 0o600);
        create_directory(&home.join("evidence/keep"), PRIVATE_DIRECTORY_MODE);
        write_file(&home.join("evidence/keep/result.json"), b"evidence", 0o600);
        create_directory(&home.join("secrets"), PRIVATE_DIRECTORY_MODE);
        write_file(&home.join("secrets/api-key"), b"secret", 0o600);

        let reference_values =
            CoreUpdatePruneReferences::new(vec![recovery.clone()], vec![active_workspace.clone()]);
        let references = Arc::new(ReferenceMock::new(reference_values));
        let owner_user_id = fs::metadata(temporary.path()).expect("owner").uid();
        let io = Arc::new(PruneIoMock::new(owner_user_id));
        let artifacts: Arc<dyn CoreUpdateArtifactIo> =
            Arc::new(FilesystemCoreUpdateArtifactIo::new(owner_user_id));
        let provider = ReferenceAwareCoreUpdatePruneProvider::new(
            home.clone(),
            artifacts,
            io.clone(),
            references.clone(),
        )
        .expect("provider");
        Self {
            temporary,
            home,
            active,
            recovery,
            stale,
            active_workspace,
            stale_workspace,
            references,
            io,
            provider,
        }
    }

    // Returns one stable update identity unrelated to every fixture workspace.
    fn update_id(&self) -> Sha256Digest {
        digest('f')
    }
}

impl Drop for TestEnvironment {
    // Restores fixture permissions before TempDir recursively removes retained identities.
    fn drop(&mut self) {
        make_tree_writable(self.temporary.path());
    }
}

// Imports the Unix metadata extension only where fixture ownership is resolved.
use std::os::unix::fs::MetadataExt;

// Returns one exact immutable Core path under the fixture versions root.
fn core_path(home: &Path, installation: &CoreInstallation) -> PathBuf {
    home.join("core/versions")
        .join(installation.version().as_str())
        .join(installation.source_identity().as_str())
}

// Creates one complete immutable native Core identity with a self-hashing release manifest.
fn create_core(home: &Path, version: &str, payload: &[u8]) -> CoreInstallation {
    let payloads = [
        "bin/li_benchmark_worker",
        "bin/li_core_setup",
        "bin/li_gateway",
        "bin/li_letsinfer",
        "bin/li_node",
        "bin/li_watchdog",
    ]
    .into_iter()
    .map(|path| {
        (
            path,
            [payload, b":", version.as_bytes(), b":", path.as_bytes()].concat(),
        )
    })
    .collect::<Vec<_>>();
    let files = payloads
        .iter()
        .map(|(path, bytes)| {
            json!({
                "bytes": bytes.len(),
                "mode": 0o755,
                "path": path,
                "sha256": digest_bytes(bytes).as_str(),
            })
        })
        .collect::<Vec<_>>();
    let manifest = canonical_json(&json!({
        "schema": {"name": "li_core_release_manifest", "version": 1},
        "release": {"version": version},
        "platform": {"os": "linux", "architecture": "x86_64"},
        "files": files,
    }));
    let source_identity = digest_bytes(&manifest);
    let installation = CoreInstallation::new(
        CoreVersion::parse(version).expect("version"),
        source_identity,
    );
    let root = core_path(home, &installation);
    create_directory(&root, PRIVATE_DIRECTORY_MODE);
    for (path, bytes) in payloads {
        write_file(&root.join(path), &bytes, IMMUTABLE_DIRECTORY_MODE);
    }
    write_file(&root.join(CORE_RELEASE_MANIFEST_NAME), &manifest, 0o444);
    fs::set_permissions(
        root.join("bin"),
        fs::Permissions::from_mode(IMMUTABLE_DIRECTORY_MODE),
    )
    .expect("bin mode");
    fs::set_permissions(&root, fs::Permissions::from_mode(IMMUTABLE_DIRECTORY_MODE))
        .expect("root mode");
    fs::set_permissions(
        root.parent().expect("version root"),
        fs::Permissions::from_mode(VERSION_DIRECTORY_MODE),
    )
    .expect("version mode");
    installation
}

// Creates one exact private update workspace with bounded owner-only material.
fn create_workspace(home: &Path, identity: &Sha256Digest) {
    let root = home.join("core/staging").join(identity.as_str());
    create_directory(&root, PRIVATE_DIRECTORY_MODE);
    write_file(&root.join("download.part"), b"partial", 0o600);
}

// Proves active, prior recovery, and live workspace references all survive.
#[test]
fn plan_preserves_every_active_and_referenced_identity() {
    let environment = TestEnvironment::new();
    let plan = environment
        .provider
        .plan(&environment.update_id(), &environment.active)
        .expect("plan");

    assert_eq!(plan.core_installations(), &[environment.stale.clone()]);
    assert_eq!(
        plan.update_workspaces(),
        &[environment.stale_workspace.clone()]
    );
    assert_eq!(plan.version_roots(), &[environment.stale.version().clone()]);
    assert!(core_path(&environment.home, &environment.active).is_dir());
    assert!(core_path(&environment.home, &environment.recovery).is_dir());
    assert!(environment
        .home
        .join("core/staging")
        .join(environment.active_workspace.as_str())
        .is_dir());
    assert!(environment.io.removed().is_empty());
}

// Removes only planned stale roots and returns the same exact identities in its receipt.
#[test]
fn prune_removes_exact_stale_identities_and_nothing_outside_core() {
    let environment = TestEnvironment::new();
    let receipt = environment
        .provider
        .prune_with_receipt(&environment.update_id(), &environment.active, false)
        .expect("prune");

    assert_eq!(
        receipt.removed_core_installations(),
        &[environment.stale.clone()]
    );
    assert_eq!(
        receipt.removed_update_workspaces(),
        &[environment.stale_workspace.clone()]
    );
    assert!(!core_path(&environment.home, &environment.stale).exists());
    assert!(core_path(&environment.home, &environment.active).is_dir());
    assert!(core_path(&environment.home, &environment.recovery).is_dir());
    assert!(environment.home.join("models/keep/model.bin").is_file());
    assert!(environment.home.join("evidence/keep/result.json").is_file());
    assert!(environment.home.join("secrets/api-key").is_file());
}

// Rejects both content corruption and a no-follow workspace link before deletion.
#[test]
fn unsafe_or_corrupt_tree_rejection_is_fail_closed() {
    for corruption in ["core", "workspace"] {
        let environment = TestEnvironment::new();
        match corruption {
            "core" => {
                let stale_file =
                    core_path(&environment.home, &environment.stale).join("bin/li_node");
                fs::set_permissions(&stale_file, fs::Permissions::from_mode(0o755))
                    .expect("writable stale file");
                fs::write(&stale_file, b"corrupt").expect("corrupt stale file");
                fs::set_permissions(&stale_file, fs::Permissions::from_mode(0o555))
                    .expect("restore mode");
            }
            "workspace" => {
                let root = environment
                    .home
                    .join("core/staging")
                    .join(environment.stale_workspace.as_str());
                fs::remove_file(root.join("download.part")).expect("remove file");
                symlink("../escape", root.join("download.part")).expect("unsafe link");
            }
            _ => unreachable!(),
        }

        let error = environment
            .provider
            .plan(&environment.update_id(), &environment.active)
            .expect_err("unsafe layout");
        assert!(
            error.to_string().contains("unsafe"),
            "{corruption}: {error}"
        );
        assert!(environment.io.removed().is_empty());
        assert!(core_path(&environment.home, &environment.stale).exists());
    }
}

// Proves a failed manager-reference snapshot cannot cross the first mutation boundary.
#[test]
fn reference_provider_failure_performs_no_mutation() {
    let environment = TestEnvironment::new();
    environment.references.fail();

    let error = environment
        .provider
        .prune_with_receipt(&environment.update_id(), &environment.active, false)
        .expect_err("reference failure");

    assert!(error.to_string().contains("references unavailable"));
    assert!(environment.io.removed().is_empty());
    assert!(core_path(&environment.home, &environment.stale).exists());
}

// Resumes after one whole target was removed and the next exact deletion failed.
#[test]
fn partial_deletion_replans_and_retries_without_touching_retained_state() {
    let environment = TestEnvironment::new();
    environment.io.fail_remove_call(2);

    environment
        .provider
        .prune_with_receipt(&environment.update_id(), &environment.active, false)
        .expect_err("partial failure");
    assert!(!environment
        .home
        .join("core/staging")
        .join(environment.stale_workspace.as_str())
        .exists());
    let receipt = environment
        .provider
        .prune_with_receipt(&environment.update_id(), &environment.active, false)
        .expect("retry");
    assert!(receipt.removed_update_workspaces().is_empty());
    assert_eq!(
        receipt.removed_core_installations(),
        &[environment.stale.clone()]
    );
    assert!(core_path(&environment.home, &environment.active).is_dir());
    assert!(core_path(&environment.home, &environment.recovery).is_dir());
}

// Returns one stable empty receipt when an already-completed prune is replayed.
#[test]
fn completed_prune_replays_as_the_same_empty_receipt() {
    let environment = TestEnvironment::new();
    environment
        .provider
        .prune_with_receipt(&environment.update_id(), &environment.active, false)
        .expect("initial prune");

    let first = environment
        .provider
        .prune_with_receipt(&environment.update_id(), &environment.active, false)
        .expect("first replay");
    let second = environment
        .provider
        .prune_with_receipt(&environment.update_id(), &environment.active, false)
        .expect("second replay");

    assert_eq!(first, second);
    assert!(first.removed_core_installations().is_empty());
    assert!(first.removed_update_workspaces().is_empty());
}
