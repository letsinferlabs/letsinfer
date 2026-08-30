// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use li_core_interface::Sha256Digest;
use li_core_update_manager::{
    ActivatedCoreUpdate, CoreInstallation, CoreUpdateArtifactEntry, CoreUpdateArtifactEntryKind,
    CoreUpdateArtifactIo, CoreUpdateArtifactProvider, CoreUpdateCandidateInstaller,
    CoreUpdateCandidateRequest, CoreUpdateError, CoreUpdatePathKind, CoreVersion,
    FilesystemCoreUpdateArtifactIo, FilesystemCoreUpdateArtifactProvider, PreparedCoreUpdate,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const PRIVATE_MODE: u32 = 0o700;
const VERSION_MODE: u32 = 0o755;
const IMMUTABLE_DIRECTORY_MODE: u32 = 0o555;
const IMMUTABLE_FILE_MODE: u32 = 0o444;
const IMMUTABLE_EXECUTABLE_MODE: u32 = 0o555;
const CORE_RELEASE_MANIFEST_NAME: &str = "li_core_release_manifest_v1.json";

// Stores one deterministic regular file in the mocked native filesystem.
#[derive(Clone)]
struct MockFile {
    bytes: Vec<u8>,
    mode: u32,
}

// Stores all deterministic native filesystem state shared across provider restarts.
#[derive(Default)]
struct MockFilesystemState {
    directories: BTreeMap<PathBuf, u32>,
    files: BTreeMap<PathBuf, MockFile>,
    links: BTreeMap<PathBuf, PathBuf>,
}

// Injects one counted failure at an exact external capability boundary.
#[derive(Default)]
struct FailurePlan {
    failures: Mutex<BTreeMap<&'static str, usize>>,
}

impl FailurePlan {
    // Schedules one failure for the next invocation of a named capability.
    fn fail(&self, capability: &'static str) {
        *self
            .failures
            .lock()
            .expect("failures")
            .entry(capability)
            .or_default() += 1;
    }

    // Returns a stable error exactly when one scheduled failure is consumed.
    fn check(&self, capability: &'static str) -> Result<(), CoreUpdateError> {
        let mut failures = self.failures.lock().expect("failures");
        let remaining = failures.entry(capability).or_default();
        if *remaining == 0 {
            return Ok(());
        }
        *remaining -= 1;
        Err(mock_error(capability))
    }
}

// Implements every native artifact operation over one deterministic in-memory tree.
struct MockArtifactIo {
    state: Mutex<MockFilesystemState>,
    failures: Arc<FailurePlan>,
    events: Arc<Mutex<Vec<String>>>,
}

impl MockArtifactIo {
    // Creates one empty deterministic filesystem capability.
    fn new(failures: Arc<FailurePlan>, events: Arc<Mutex<Vec<String>>>) -> Self {
        Self {
            state: Mutex::new(MockFilesystemState::default()),
            failures,
            events,
        }
    }

    // Adds one exact directory to the mocked filesystem.
    fn add_directory(&self, path: PathBuf, mode: u32) {
        self.state
            .lock()
            .expect("state")
            .directories
            .insert(path, mode);
    }

    // Adds one exact regular file to the mocked filesystem.
    fn add_file(&self, path: PathBuf, bytes: Vec<u8>, mode: u32) {
        self.state
            .lock()
            .expect("state")
            .files
            .insert(path, MockFile { bytes, mode });
    }

    // Adds or replaces one exact symlink in the mocked filesystem.
    fn add_link(&self, path: PathBuf, target: PathBuf) {
        self.state.lock().expect("state").links.insert(path, target);
    }

    // Materializes one complete immutable native release fixture at an exact root.
    fn materialize_source(&self, root: &Path, installation: &CoreInstallation, root_mode: u32) {
        let fixture = source_fixture(installation.version().as_str());
        assert_eq!(&fixture.identity, installation.source_identity());
        self.add_directory(root.to_path_buf(), root_mode);
        self.add_directory(root.join("bin"), IMMUTABLE_DIRECTORY_MODE);
        for (path, bytes) in fixture.payloads {
            self.add_file(root.join(path), bytes, IMMUTABLE_EXECUTABLE_MODE);
        }
        self.add_file(
            root.join(CORE_RELEASE_MANIFEST_NAME),
            fixture.manifest_bytes,
            IMMUTABLE_FILE_MODE,
        );
    }

    // Returns whether one exact path or descendant remains in native state.
    fn contains_tree(&self, root: &Path) -> bool {
        let state = self.state.lock().expect("state");
        state
            .directories
            .keys()
            .chain(state.files.keys())
            .chain(state.links.keys())
            .any(|path| path == root || path.starts_with(root))
    }

    // Appends one native operation to the deterministic event sequence.
    fn record(&self, event: &'static str) {
        self.events.lock().expect("events").push(event.to_string());
    }
}

impl CoreUpdateArtifactIo for MockArtifactIo {
    // Returns one final mocked path type without following links.
    fn path_kind(&self, path: &Path) -> Result<CoreUpdatePathKind, CoreUpdateError> {
        self.failures.check("io.path_kind")?;
        let state = self.state.lock().expect("state");
        if state.links.contains_key(path) {
            Ok(CoreUpdatePathKind::Symlink)
        } else if state.directories.contains_key(path) {
            Ok(CoreUpdatePathKind::Directory)
        } else if state.files.contains_key(path) {
            Ok(CoreUpdatePathKind::RegularFile)
        } else {
            Ok(CoreUpdatePathKind::Missing)
        }
    }

    // Requires one exact mocked directory and permission mode.
    fn require_directory(&self, path: &Path, mode: u32) -> Result<(), CoreUpdateError> {
        self.failures.check("io.require_directory")?;
        let state = self.state.lock().expect("state");
        if state.directories.get(path) == Some(&mode)
            && !state.links.contains_key(path)
            && !state.files.contains_key(path)
        {
            Ok(())
        } else {
            Err(mock_error("unsafe directory"))
        }
    }

    // Reads one exact mocked symlink target without resolving it.
    fn read_symlink(&self, path: &Path) -> Result<PathBuf, CoreUpdateError> {
        self.failures.check("io.read_symlink")?;
        self.state
            .lock()
            .expect("state")
            .links
            .get(path)
            .cloned()
            .ok_or_else(|| mock_error("unsafe symlink"))
    }

    // Reads one bounded mocked regular file without following links.
    fn read_regular_file(
        &self,
        path: &Path,
        maximum_bytes: u64,
    ) -> Result<Vec<u8>, CoreUpdateError> {
        self.failures.check("io.read_regular_file")?;
        let state = self.state.lock().expect("state");
        let file = state
            .files
            .get(path)
            .ok_or_else(|| mock_error("unsafe regular file"))?;
        if state.links.contains_key(path) || file.bytes.len() as u64 > maximum_bytes {
            return Err(mock_error("unsafe regular file"));
        }
        Ok(file.bytes.clone())
    }

    // Inventories one mocked immutable tree and rejects every contained symlink.
    fn inventory(&self, root: &Path) -> Result<Vec<CoreUpdateArtifactEntry>, CoreUpdateError> {
        self.failures.check("io.inventory")?;
        let state = self.state.lock().expect("state");
        if state
            .links
            .keys()
            .any(|path| path != root && path.starts_with(root))
        {
            return Err(mock_error("unsafe inventory"));
        }
        let mut entries = Vec::new();
        for (path, mode) in &state.directories {
            if path == root || !path.starts_with(root) {
                continue;
            }
            entries.push(CoreUpdateArtifactEntry::directory(
                path.strip_prefix(root).expect("relative").to_path_buf(),
                *mode,
            )?);
        }
        for (path, file) in &state.files {
            if !path.starts_with(root) {
                continue;
            }
            entries.push(CoreUpdateArtifactEntry::regular_file(
                path.strip_prefix(root).expect("relative").to_path_buf(),
                file.mode,
                file.bytes.len() as u64,
                digest_bytes(&file.bytes),
            )?);
        }
        entries.sort_by(|left, right| left.relative_path().cmp(right.relative_path()));
        Ok(entries)
    }

    // Creates or validates one private mocked update workspace.
    fn prepare_workspace(&self, path: &Path) -> Result<(), CoreUpdateError> {
        self.record("io.prepare_workspace");
        self.failures.check("io.prepare_workspace")?;
        let parent = path.parent().expect("workspace parent").to_path_buf();
        let mut state = self.state.lock().expect("state");
        state.directories.entry(parent).or_insert(PRIVATE_MODE);
        state
            .directories
            .entry(path.to_path_buf())
            .or_insert(PRIVATE_MODE);
        Ok(())
    }

    // Creates or validates one mocked immutable version directory.
    fn prepare_version_directory(&self, path: &Path) -> Result<(), CoreUpdateError> {
        self.record("io.prepare_version_directory");
        self.failures.check("io.prepare_version_directory")?;
        let mut state = self.state.lock().expect("state");
        if state.links.contains_key(path) || state.files.contains_key(path) {
            return Err(mock_error("unsafe version directory"));
        }
        match state.directories.get(path) {
            Some(mode) if *mode != VERSION_MODE => Err(mock_error("unsafe version directory")),
            Some(_) => Ok(()),
            None => {
                state.directories.insert(path.to_path_buf(), VERSION_MODE);
                Ok(())
            }
        }
    }

    // Atomically relocates one mocked immutable native tree.
    fn install_immutable_tree(
        &self,
        source: &Path,
        destination: &Path,
    ) -> Result<(), CoreUpdateError> {
        self.record("io.install_immutable_tree");
        self.failures.check("io.install_immutable_tree")?;
        let mut state = self.state.lock().expect("state");
        if state.directories.contains_key(destination) {
            return Ok(());
        }
        if state.directories.get(source) != Some(&PRIVATE_MODE) {
            return Err(mock_error("missing staged source"));
        }
        let directories = state
            .directories
            .iter()
            .filter(|(path, _)| *path == source || path.starts_with(source))
            .map(|(path, mode)| (path.clone(), *mode))
            .collect::<Vec<_>>();
        let files = state
            .files
            .iter()
            .filter(|(path, _)| path.starts_with(source))
            .map(|(path, file)| (path.clone(), file.clone()))
            .collect::<Vec<_>>();
        for (path, _) in &directories {
            state.directories.remove(path);
        }
        for (path, _) in &files {
            state.files.remove(path);
        }
        for (path, mode) in directories {
            let relative = path.strip_prefix(source).expect("relative");
            state.directories.insert(
                destination.join(relative),
                if path == source {
                    IMMUTABLE_DIRECTORY_MODE
                } else {
                    mode
                },
            );
        }
        for (path, file) in files {
            let relative = path.strip_prefix(source).expect("relative");
            state.files.insert(destination.join(relative), file);
        }
        Ok(())
    }

    // Atomically replaces one mocked managed symlink or leaves it unchanged on failure.
    fn replace_symlink(
        &self,
        link: &Path,
        expected: &Path,
        destination: &Path,
        _temporary: &Path,
    ) -> Result<(), CoreUpdateError> {
        self.record("io.replace_symlink");
        self.failures.check("io.replace_symlink")?;
        let mut state = self.state.lock().expect("state");
        let observed = state
            .links
            .get(link)
            .ok_or_else(|| mock_error("missing active pointer"))?;
        if observed == destination {
            return Ok(());
        }
        if observed != expected {
            return Err(mock_error("active pointer conflict"));
        }
        state
            .links
            .insert(link.to_path_buf(), destination.to_path_buf());
        Ok(())
    }

    // Persists one mocked directory at the commit or rollback boundary.
    fn sync_directory(&self, _path: &Path) -> Result<(), CoreUpdateError> {
        self.record("io.sync_directory");
        self.failures.check("io.sync_directory")
    }

    // Removes one exact mocked workspace and no neighboring state.
    fn remove_workspace(&self, path: &Path) -> Result<(), CoreUpdateError> {
        self.record("io.remove_workspace");
        self.failures.check("io.remove_workspace")?;
        let mut state = self.state.lock().expect("state");
        if state.links.keys().any(|entry| entry.starts_with(path)) {
            return Err(mock_error("unsafe workspace"));
        }
        state
            .directories
            .retain(|entry, _| !entry.starts_with(path));
        state.files.retain(|entry, _| !entry.starts_with(path));
        Ok(())
    }
}

// Materializes deterministic candidate bytes through the provider-selected destination.
struct CandidateInstallerMock {
    candidate: CoreInstallation,
    io: Arc<MockArtifactIo>,
    failures: Arc<FailurePlan>,
    events: Arc<Mutex<Vec<String>>>,
}

// Materializes deterministic immutable fixtures through real filesystem operations.
struct FilesystemCandidateInstaller {
    candidate: CoreInstallation,
}

impl CoreUpdateCandidateInstaller for FilesystemCandidateInstaller {
    // Writes one exact immutable candidate or validates its idempotent presence.
    fn prepare(
        &self,
        request: &CoreUpdateCandidateRequest,
    ) -> Result<CoreInstallation, CoreUpdateError> {
        if !request.release_root().exists() {
            write_source_tree(request.release_root(), &self.candidate, PRIVATE_MODE)?;
        }
        Ok(self.candidate.clone())
    }
}

impl CoreUpdateCandidateInstaller for CandidateInstallerMock {
    // Resolves and materializes one exact candidate idempotently.
    fn prepare(
        &self,
        request: &CoreUpdateCandidateRequest,
    ) -> Result<CoreInstallation, CoreUpdateError> {
        self.events
            .lock()
            .expect("events")
            .push("installer.prepare".to_string());
        self.failures.check("installer.prepare.before")?;
        if !self.io.contains_tree(request.release_root()) {
            self.io
                .materialize_source(request.release_root(), &self.candidate, PRIVATE_MODE);
        }
        self.failures.check("installer.prepare.after")?;
        Ok(self.candidate.clone())
    }
}

// Groups one provider with all deterministic capabilities needed for inspection.
struct TestEnvironment {
    home: PathBuf,
    provider: FilesystemCoreUpdateArtifactProvider,
    io: Arc<MockArtifactIo>,
    installer: Arc<CandidateInstallerMock>,
    failures: Arc<FailurePlan>,
    events: Arc<Mutex<Vec<String>>>,
    current: CoreInstallation,
    candidate: CoreInstallation,
}

impl TestEnvironment {
    // Reconstructs a provider over the same native state to simulate process restart.
    fn restarted_provider(&self) -> FilesystemCoreUpdateArtifactProvider {
        FilesystemCoreUpdateArtifactProvider::new(
            self.home.clone(),
            self.io.clone(),
            self.installer.clone(),
        )
        .expect("provider")
    }

    // Returns one exact update workspace path.
    fn workspace(&self, update_id: &Sha256Digest) -> PathBuf {
        self.home.join("core/staging").join(update_id.as_str())
    }

    // Returns one exact immutable installation path.
    fn installation_path(&self, installation: &CoreInstallation) -> PathBuf {
        self.home
            .join("core/versions")
            .join(installation.version().as_str())
            .join(installation.source_identity().as_str())
    }

    // Returns the current managed pointer path.
    fn current_link(&self) -> PathBuf {
        self.home.join("core/current")
    }
}

// Stores one native release fixture and its content-addressed manifest identity.
struct SourceFixture {
    payloads: BTreeMap<PathBuf, Vec<u8>>,
    manifest_bytes: Vec<u8>,
    identity: Sha256Digest,
}

// Creates one complete deterministic production-provider composition.
fn environment(current_version: &str, candidate_version: &str) -> TestEnvironment {
    let home = PathBuf::from("/mock/letsinfer");
    let current = installation(current_version);
    let candidate = installation(candidate_version);
    let failures = Arc::new(FailurePlan::default());
    let events = Arc::new(Mutex::new(Vec::new()));
    let io = Arc::new(MockArtifactIo::new(
        Arc::clone(&failures),
        Arc::clone(&events),
    ));
    io.add_directory(home.clone(), PRIVATE_MODE);
    io.add_directory(home.join("core"), PRIVATE_MODE);
    io.add_directory(home.join("core/versions"), VERSION_MODE);
    io.add_directory(
        home.join("core/versions").join(current.version().as_str()),
        VERSION_MODE,
    );
    let current_path = home
        .join("core/versions")
        .join(current.version().as_str())
        .join(current.source_identity().as_str());
    io.materialize_source(&current_path, &current, IMMUTABLE_DIRECTORY_MODE);
    io.add_link(home.join("core/current"), current_path);
    let installer = Arc::new(CandidateInstallerMock {
        candidate: candidate.clone(),
        io: Arc::clone(&io),
        failures: Arc::clone(&failures),
        events: Arc::clone(&events),
    });
    let provider =
        FilesystemCoreUpdateArtifactProvider::new(home.clone(), io.clone(), installer.clone())
            .expect("provider");
    TestEnvironment {
        home,
        provider,
        io,
        installer,
        failures,
        events,
        current,
        candidate,
    }
}

// Returns one exact immutable Core installation fixture.
fn installation(version: &str) -> CoreInstallation {
    let fixture = source_fixture(version);
    CoreInstallation::new(
        CoreVersion::parse(version).expect("version"),
        fixture.identity,
    )
}

// Creates one closed native manifest whose bytes bind the fixture version and files.
fn source_fixture(version: &str) -> SourceFixture {
    let paths = [
        "bin/li_benchmark_worker",
        "bin/li_core_setup",
        "bin/li_gateway",
        "bin/li_letsinfer",
        "bin/li_node",
        "bin/li_watchdog",
    ];
    let payloads = paths
        .iter()
        .map(|path| {
            (
                PathBuf::from(path),
                format!("native:{version}:{path}\n").into_bytes(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let files = payloads
        .iter()
        .map(|(path, bytes)| {
            json!({
                "path": path.to_str().expect("path"),
                "bytes": bytes.len(),
                "mode": 0o755,
                "sha256": digest_bytes(bytes).as_str(),
            })
        })
        .collect::<Vec<_>>();
    let mut manifest_bytes = serde_json::to_vec(&json!({
        "schema": {"name": "li_core_release_manifest", "version": 1},
        "release": {"version": version},
        "platform": {"os": "linux", "architecture": "x86_64"},
        "files": files,
    }))
    .expect("manifest");
    manifest_bytes.push(b'\n');
    SourceFixture {
        identity: digest_bytes(&manifest_bytes),
        payloads,
        manifest_bytes,
    }
}

// Returns one exact lowercase SHA-256 identity for fixture bytes.
fn digest_bytes(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::parse(&format!("{:x}", Sha256::digest(bytes))).expect("digest")
}

// Returns one exact lowercase SHA-256 fixture.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&character.to_string().repeat(64)).expect("digest")
}

// Returns one stable redacted error from a deterministic mocked boundary.
fn mock_error(_capability: &'static str) -> CoreUpdateError {
    CoreUpdateError::provider("mock", "injected failure")
}

// Returns the deterministic external operation sequence.
fn events(environment: &TestEnvironment) -> Vec<String> {
    environment.events.lock().expect("events").clone()
}

// Creates one real immutable Core layout and its filesystem-backed provider.
fn filesystem_environment(
    current_version: &str,
    candidate_version: &str,
) -> Result<
    (
        TempDir,
        PathBuf,
        CoreInstallation,
        CoreInstallation,
        FilesystemCoreUpdateArtifactProvider,
    ),
    CoreUpdateError,
> {
    let temporary = tempfile::tempdir().map_err(|_| mock_error("temporary directory"))?;
    let owner_user_id = fs::metadata(temporary.path())
        .map_err(|_| mock_error("temporary metadata"))?
        .uid();
    let home = temporary.path().join("letsinfer");
    let current = installation(current_version);
    let candidate = installation(candidate_version);
    create_directory(&home, PRIVATE_MODE)?;
    create_directory(&home.join("core"), PRIVATE_MODE)?;
    create_directory(&home.join("core/versions"), VERSION_MODE)?;
    let version_root = home.join("core/versions").join(current.version().as_str());
    create_directory(&version_root, VERSION_MODE)?;
    let current_root = version_root.join(current.source_identity().as_str());
    write_source_tree(&current_root, &current, IMMUTABLE_DIRECTORY_MODE)?;
    symlink(&current_root, home.join("core/current")).map_err(|_| mock_error("current symlink"))?;
    let provider = FilesystemCoreUpdateArtifactProvider::new(
        home.clone(),
        Arc::new(FilesystemCoreUpdateArtifactIo::new(owner_user_id)),
        Arc::new(FilesystemCandidateInstaller {
            candidate: candidate.clone(),
        }),
    )?;
    Ok((temporary, home, current, candidate, provider))
}

// Writes one complete native fixture before sealing every path to installed modes.
fn write_source_tree(
    root: &Path,
    installation: &CoreInstallation,
    root_mode: u32,
) -> Result<(), CoreUpdateError> {
    let fixture = source_fixture(installation.version().as_str());
    if fixture.identity != *installation.source_identity() {
        return Err(mock_error("fixture identity"));
    }
    fs::create_dir(root).map_err(|_| mock_error("native root"))?;
    fs::create_dir(root.join("bin")).map_err(|_| mock_error("native directory"))?;
    for (path, bytes) in fixture.payloads {
        let destination = root.join(path);
        fs::write(&destination, bytes).map_err(|_| mock_error("native file"))?;
        fs::set_permissions(
            destination,
            fs::Permissions::from_mode(IMMUTABLE_EXECUTABLE_MODE),
        )
        .map_err(|_| mock_error("native mode"))?;
    }
    fs::write(
        root.join(CORE_RELEASE_MANIFEST_NAME),
        fixture.manifest_bytes,
    )
    .map_err(|_| mock_error("manifest file"))?;
    fs::set_permissions(
        root.join(CORE_RELEASE_MANIFEST_NAME),
        fs::Permissions::from_mode(IMMUTABLE_FILE_MODE),
    )
    .map_err(|_| mock_error("manifest mode"))?;
    fs::set_permissions(
        root.join("bin"),
        fs::Permissions::from_mode(IMMUTABLE_DIRECTORY_MODE),
    )
    .map_err(|_| mock_error("directory mode"))?;
    fs::set_permissions(root, fs::Permissions::from_mode(root_mode))
        .map_err(|_| mock_error("root mode"))
}

// Creates one directory and immediately applies its exact Unix mode.
fn create_directory(path: &Path, mode: u32) -> Result<(), CoreUpdateError> {
    fs::create_dir(path).map_err(|_| mock_error("directory creation"))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|_| mock_error("directory mode"))
}

// Restores writable test-fixture modes before the temporary root is removed.
fn make_test_tree_writable(root: &Path) {
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let _ = fs::set_permissions(&directory, fs::Permissions::from_mode(PRIVATE_MODE));
        if let Ok(entries) = fs::read_dir(&directory) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_symlink() {
                    continue;
                }
                if path.is_dir() {
                    pending.push(path);
                } else {
                    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
                }
            }
        }
    }
}

// Validates the exact current pointer, version path, manifest, and source inventory.
#[test]
fn current_validates_the_complete_immutable_layout() {
    let environment = environment("1.0.0", "1.1.0");
    assert_eq!(
        environment.provider.current(&digest('a')).expect("current"),
        environment.current
    );
    assert!(events(&environment).is_empty());
}

// Replays prepare, activation, restart, and commit without duplicating native mutation.
#[test]
fn successful_handoff_and_restart_replay_are_idempotent() {
    let environment = environment("1.0.0", "1.1.0");
    let update_id = digest('a');
    let prepared = environment
        .provider
        .prepare(&update_id, None, &environment.current)
        .expect("prepare");
    let prepared_replay = environment
        .provider
        .prepare(&update_id, None, &environment.current)
        .expect("prepare replay");
    assert_eq!(prepared_replay, prepared);

    let activation = environment
        .provider
        .activate(&update_id, &prepared, &environment.current)
        .expect("activate");
    let restarted = environment.restarted_provider();
    assert_eq!(
        restarted
            .activate(&update_id, &prepared, &environment.current)
            .expect("activation replay"),
        activation
    );
    restarted.commit(&update_id, &activation).expect("commit");
    restarted
        .commit(&update_id, &activation)
        .expect("commit replay");

    assert_eq!(
        restarted.current(&update_id).expect("current"),
        environment.candidate
    );
    assert!(!environment
        .io
        .contains_tree(&environment.workspace(&update_id)));
    assert_eq!(
        events(&environment)
            .iter()
            .filter(|event| event.as_str() == "io.install_immutable_tree")
            .count(),
        1
    );
    assert_eq!(
        events(&environment)
            .iter()
            .filter(|event| event.as_str() == "io.replace_symlink")
            .count(),
        1
    );
}

// Discards a verified current candidate without touching the active pointer or neighbors.
#[test]
fn current_candidate_discard_removes_only_its_workspace() {
    let environment = environment("1.0.0", "1.0.0");
    let update_id = digest('b');
    let prepared = environment
        .provider
        .prepare(&update_id, None, &environment.current)
        .expect("prepare");
    let neighbor = environment.home.join("core/staging").join("f".repeat(64));
    environment.io.add_directory(neighbor.clone(), PRIVATE_MODE);
    environment
        .provider
        .discard(&update_id, &prepared)
        .expect("discard");
    environment
        .provider
        .discard(&update_id, &prepared)
        .expect("discard replay");
    assert!(!environment
        .io
        .contains_tree(&environment.workspace(&update_id)));
    assert!(environment.io.contains_tree(&neighbor));
    assert_eq!(
        environment.provider.current(&update_id).expect("current"),
        environment.current
    );
}

// Cleans exact staging after each meaningful preparation boundary fails.
#[test]
fn preparation_failure_boundaries_leave_no_partial_workspace() {
    for capability in [
        "io.prepare_workspace",
        "installer.prepare.before",
        "installer.prepare.after",
        "io.read_regular_file",
        "io.inventory",
    ] {
        let environment = environment("1.0.0", "1.1.0");
        let update_id = digest('c');
        environment.failures.fail(capability);
        assert!(environment
            .provider
            .prepare(&update_id, None, &environment.current)
            .is_err());
        assert!(
            !environment
                .io
                .contains_tree(&environment.workspace(&update_id)),
            "workspace survived {capability}"
        );
        assert_eq!(
            environment.provider.current(&update_id).expect("current"),
            environment.current
        );
    }
}

// Keeps the previous Core active when any pre-pointer activation mutation fails.
#[test]
fn activation_mutation_boundaries_fail_before_pointer_handoff() {
    for capability in [
        "io.prepare_version_directory",
        "io.install_immutable_tree",
        "io.replace_symlink",
    ] {
        let environment = environment("1.0.0", "1.1.0");
        let update_id = digest('d');
        let prepared = environment
            .provider
            .prepare(&update_id, None, &environment.current)
            .expect("prepare");
        environment.failures.fail(capability);
        assert!(environment
            .provider
            .activate(&update_id, &prepared, &environment.current)
            .is_err());
        assert_eq!(
            environment.provider.current(&update_id).expect("current"),
            environment.current,
            "pointer changed at {capability}"
        );
        environment
            .provider
            .discard(&update_id, &prepared)
            .expect("discard");
    }
}

// Restores the exact previous Core and replays rollback without deleting the candidate.
#[test]
fn rollback_restores_exact_previous_core_and_is_idempotent() {
    let environment = environment("1.0.0", "1.1.0");
    let update_id = digest('e');
    let prepared = environment
        .provider
        .prepare(&update_id, None, &environment.current)
        .expect("prepare");
    let activation = environment
        .provider
        .activate(&update_id, &prepared, &environment.current)
        .expect("activate");
    let restarted = environment.restarted_provider();
    restarted
        .rollback(&update_id, &activation)
        .expect("rollback");
    restarted
        .rollback(&update_id, &activation)
        .expect("rollback replay");
    assert_eq!(
        restarted.current(&update_id).expect("current"),
        environment.current
    );
    assert!(environment
        .io
        .contains_tree(&environment.installation_path(&environment.candidate)));
    assert!(!environment
        .io
        .contains_tree(&environment.workspace(&update_id)));
}

// Retries each rollback mutation boundary until the exact previous Core is restored.
#[test]
fn rollback_mutation_boundaries_resume_without_cross_update_cleanup() {
    for capability in [
        "io.replace_symlink",
        "io.sync_directory",
        "io.remove_workspace",
    ] {
        let environment = environment("1.0.0", "1.1.0");
        let update_id = digest('e');
        let prepared = environment
            .provider
            .prepare(&update_id, None, &environment.current)
            .expect("prepare");
        let activation = environment
            .provider
            .activate(&update_id, &prepared, &environment.current)
            .expect("activate");
        environment.failures.fail(capability);
        assert!(environment
            .provider
            .rollback(&update_id, &activation)
            .is_err());
        environment
            .provider
            .rollback(&update_id, &activation)
            .expect("rollback retry");
        assert_eq!(
            environment.provider.current(&update_id).expect("current"),
            environment.current,
            "previous Core was not restored after {capability}"
        );
        assert!(!environment
            .io
            .contains_tree(&environment.workspace(&update_id)));
    }
}

// Retries commit persistence and cleanup failures without changing the candidate pointer.
#[test]
fn commit_mutation_boundaries_retry_the_same_candidate() {
    for capability in ["io.sync_directory", "io.remove_workspace"] {
        let environment = environment("1.0.0", "1.1.0");
        let update_id = digest('f');
        let prepared = environment
            .provider
            .prepare(&update_id, None, &environment.current)
            .expect("prepare");
        let activation = environment
            .provider
            .activate(&update_id, &prepared, &environment.current)
            .expect("activate");
        environment.failures.fail(capability);
        assert!(environment
            .provider
            .commit(&update_id, &activation)
            .is_err());
        assert_eq!(
            environment.provider.current(&update_id).expect("current"),
            environment.candidate
        );
        environment
            .provider
            .commit(&update_id, &activation)
            .expect("commit retry");
        assert!(!environment
            .io
            .contains_tree(&environment.workspace(&update_id)));
    }
}

// Rejects foreign receipts before they can remove staging or move the current pointer.
#[test]
fn foreign_receipts_cannot_mutate_provider_state() {
    let environment = environment("1.0.0", "1.1.0");
    let update_id = digest('a');
    let prepared = environment
        .provider
        .prepare(&update_id, None, &environment.current)
        .expect("prepare");
    let foreign_prepared = PreparedCoreUpdate::new(digest('0'), environment.candidate.clone());
    assert!(environment
        .provider
        .discard(&update_id, &foreign_prepared)
        .is_err());
    assert!(environment
        .io
        .contains_tree(&environment.workspace(&update_id)));
    let foreign_activation = ActivatedCoreUpdate::new(
        digest('1'),
        environment.current.clone(),
        environment.candidate.clone(),
    )
    .expect("activation");
    assert!(environment
        .provider
        .rollback(&update_id, &foreign_activation)
        .is_err());
    assert_eq!(
        environment.provider.current(&update_id).expect("current"),
        environment.current
    );
    environment
        .provider
        .discard(&update_id, &prepared)
        .expect("discard valid");
}

// Rejects unsafe pointer, mode, manifest, inventory, and contained-link layouts.
#[test]
fn unsafe_layout_matrix_fails_closed() {
    {
        let environment = environment("1.0.0", "1.1.0");
        environment
            .io
            .add_link(environment.current_link(), PathBuf::from("relative/core"));
        assert!(environment.provider.current(&digest('a')).is_err());
    }
    {
        let environment = environment("1.0.0", "1.1.0");
        environment
            .io
            .add_directory(environment.home.join("core/versions"), PRIVATE_MODE);
        assert!(environment.provider.current(&digest('a')).is_err());
    }
    {
        let environment = environment("1.0.0", "1.1.0");
        let root = environment.installation_path(&environment.current);
        environment.io.add_file(
            root.join("foreign-release-file.json"),
            b"{}".to_vec(),
            IMMUTABLE_FILE_MODE,
        );
        assert!(environment.provider.current(&digest('a')).is_err());
    }
    {
        let environment = environment("1.0.0", "1.1.0");
        let root = environment.installation_path(&environment.current);
        environment.io.add_file(
            root.join("unexpected"),
            b"unexpected".to_vec(),
            IMMUTABLE_FILE_MODE,
        );
        assert!(environment.provider.current(&digest('a')).is_err());
    }
    {
        let environment = environment("1.0.0", "1.1.0");
        let root = environment.installation_path(&environment.current);
        environment
            .io
            .add_link(root.join("core/escape"), PathBuf::from("/outside"));
        assert!(environment.provider.current(&digest('a')).is_err());
    }
}

// Keeps the entry-kind constructor contract closed over directories and regular files.
#[test]
fn inventory_entry_contract_rejects_unsafe_relative_paths() {
    assert!(CoreUpdateArtifactEntry::directory(PathBuf::from("../escape"), 0o555).is_err());
    let entry = CoreUpdateArtifactEntry::regular_file(
        PathBuf::from("bin/letsinfer"),
        0o555,
        1,
        digest('a'),
    )
    .expect("entry");
    assert_eq!(entry.kind(), CoreUpdateArtifactEntryKind::RegularFile);
}

// Exercises the real no-follow filesystem capability through activation and rollback.
#[test]
fn filesystem_provider_atomically_activates_and_restores_exact_core() {
    let (temporary, home, current, candidate, provider) =
        filesystem_environment("1.0.0", "1.1.0").expect("environment");
    let update_id = digest('a');
    let prepared = provider
        .prepare(&update_id, None, &current)
        .expect("prepare");
    let activation = provider
        .activate(&update_id, &prepared, &current)
        .expect("activate");
    assert_eq!(provider.current(&update_id).expect("candidate"), candidate);
    provider
        .rollback(&update_id, &activation)
        .expect("rollback");
    assert_eq!(provider.current(&update_id).expect("previous"), current);
    make_test_tree_writable(&home);
    drop(temporary);
}

// Proves the real inventory refuses contained symbolic and hard links.
#[test]
fn filesystem_provider_rejects_contained_links_without_following_them() {
    let (temporary, home, current, _candidate, provider) =
        filesystem_environment("1.0.0", "1.1.0").expect("environment");
    let current_root = home
        .join("core/versions")
        .join(current.version().as_str())
        .join(current.source_identity().as_str());
    fs::set_permissions(
        current_root.join("bin"),
        fs::Permissions::from_mode(VERSION_MODE),
    )
    .expect("writable directory");
    symlink(
        current_root.join("bin/li_node"),
        current_root.join("bin/alias"),
    )
    .expect("nested symlink");
    fs::set_permissions(
        current_root.join("bin"),
        fs::Permissions::from_mode(IMMUTABLE_DIRECTORY_MODE),
    )
    .expect("sealed directory");
    assert!(provider.current(&digest('a')).is_err());
    fs::set_permissions(
        current_root.join("bin"),
        fs::Permissions::from_mode(VERSION_MODE),
    )
    .expect("writable directory");
    fs::remove_file(current_root.join("bin/alias")).expect("remove symlink");
    fs::hard_link(
        current_root.join("bin/li_node"),
        current_root.join("bin/alias"),
    )
    .expect("nested hard link");
    fs::set_permissions(
        current_root.join("bin"),
        fs::Permissions::from_mode(IMMUTABLE_DIRECTORY_MODE),
    )
    .expect("sealed directory");
    assert!(provider.current(&digest('a')).is_err());
    make_test_tree_writable(&home);
    drop(temporary);
}
