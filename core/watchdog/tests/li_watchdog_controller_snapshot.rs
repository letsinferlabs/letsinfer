// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use li_watchdog_manager::{
    FilesystemWatchdogControllerSnapshotProvider, SystemWatchdogControllerSnapshotIo,
    WatchdogControllerAllowlist, WatchdogControllerBinding, WatchdogControllerMutationKind,
    WatchdogControllerRegistry, WatchdogControllerRegistryStore, WatchdogControllerSnapshotFile,
    WatchdogControllerSnapshotIo, WatchdogError, WatchdogProtectedEngine,
};
use tempfile::tempdir;

const SNAPSHOT_PATH: &str = "/private/li_watchdog_controller_registry.snapshot";

// Stores one cloneable snapshot descriptor observation.
#[derive(Clone)]
struct MockSnapshotFile {
    owner_user_id: u32,
    mode: u32,
    link_count: u64,
    is_regular_file: bool,
    bytes: Vec<u8>,
}

impl MockSnapshotFile {
    // Creates one safe private snapshot observation.
    fn safe(bytes: Vec<u8>) -> Self {
        Self {
            owner_user_id: 501,
            mode: 0o600,
            link_count: 1,
            is_regular_file: true,
            bytes,
        }
    }

    // Converts the cloneable fixture into the provider's zeroing observation.
    fn observation(&self) -> WatchdogControllerSnapshotFile {
        WatchdogControllerSnapshotFile::new(
            self.owner_user_id,
            self.mode,
            self.link_count,
            self.is_regular_file,
            self.bytes.clone(),
        )
    }
}

// Supplies deterministic atomic file behavior and injected replacement failure.
struct MockSnapshotIo {
    files: Mutex<BTreeMap<PathBuf, MockSnapshotFile>>,
    fail_replace: AtomicBool,
}

impl MockSnapshotIo {
    // Creates one empty deterministic snapshot filesystem.
    fn new() -> Self {
        Self {
            files: Mutex::new(BTreeMap::new()),
            fail_replace: AtomicBool::new(false),
        }
    }

    // Returns the exact currently committed bytes for assertions.
    fn bytes(&self, path: &str) -> Vec<u8> {
        self.files.lock().unwrap()[&PathBuf::from(path)]
            .bytes
            .clone()
    }

    // Replaces one file outside the provider to inject an optimistic conflict.
    fn replace_external(&self, path: &str, file: MockSnapshotFile) {
        self.files.lock().unwrap().insert(PathBuf::from(path), file);
    }
}

impl WatchdogControllerSnapshotIo for MockSnapshotIo {
    // Returns one cloned observation or an absent-file result.
    fn read_no_follow(
        &self,
        path: &Path,
        _maximum_bytes: usize,
    ) -> Result<Option<WatchdogControllerSnapshotFile>, WatchdogError> {
        Ok(self
            .files
            .lock()
            .unwrap()
            .get(path)
            .map(MockSnapshotFile::observation))
    }

    // Commits all bytes together or fails without mutating the current file.
    fn replace_atomically(
        &self,
        path: &Path,
        owner_user_id: u32,
        mode: u32,
        bytes: &[u8],
    ) -> Result<(), WatchdogError> {
        if self.fail_replace.load(Ordering::Acquire) {
            return Err(WatchdogError::provider(
                "test snapshot I/O",
                "partial replacement failed",
            ));
        }
        self.files.lock().unwrap().insert(
            path.to_path_buf(),
            MockSnapshotFile {
                owner_user_id,
                mode,
                link_count: 1,
                is_regular_file: true,
                bytes: bytes.to_vec(),
            },
        );
        Ok(())
    }
}

// Proves restart reconstruction retains active and retired anti-replay generations.
#[test]
fn persistent_registry_reconstructs_before_replay_and_retirement() {
    let io = Arc::new(MockSnapshotIo::new());
    let allowlist = allowlist('f');
    let registry = WatchdogControllerRegistry::open_persistent(
        allowlist.clone(),
        1,
        snapshot_provider(io.clone()),
    )
    .unwrap();
    let active = binding(1, 'a', 101);
    registry
        .apply(active.clone(), registry.revision().unwrap())
        .unwrap();
    assert_eq!(io.bytes(SNAPSHOT_PATH), registry.snapshot().unwrap());

    let restored = WatchdogControllerRegistry::open_persistent(
        allowlist.clone(),
        1,
        snapshot_provider(io.clone()),
    )
    .unwrap();
    assert_eq!(restored.active_bindings().unwrap(), vec![active.clone()]);
    assert_eq!(
        restored
            .apply(active.clone(), restored.revision().unwrap())
            .unwrap()
            .kind(),
        WatchdogControllerMutationKind::Replayed
    );
    restored
        .retire(
            active.controller_id(),
            active.session_generation(),
            restored.revision().unwrap(),
        )
        .unwrap();

    let retired =
        WatchdogControllerRegistry::open_persistent(allowlist, 1, snapshot_provider(io)).unwrap();
    assert!(retired.apply(active, retired.revision().unwrap()).is_err());
}

// Proves partial replacement and external conflict leave in-memory state unchanged.
#[test]
fn persistent_registry_rolls_back_partial_write_and_rejects_conflict() {
    let io = Arc::new(MockSnapshotIo::new());
    let registry = WatchdogControllerRegistry::open_persistent(
        allowlist('f'),
        1,
        snapshot_provider(io.clone()),
    )
    .unwrap();
    let initial_snapshot = registry.snapshot().unwrap();
    io.fail_replace.store(true, Ordering::Release);
    assert!(registry.apply(binding(1, 'a', 101), 1).is_err());
    assert_eq!(registry.revision().unwrap(), 1);
    assert!(registry.active_bindings().unwrap().is_empty());
    assert_eq!(io.bytes(SNAPSHOT_PATH), initial_snapshot);

    io.fail_replace.store(false, Ordering::Release);
    io.replace_external(
        SNAPSHOT_PATH,
        MockSnapshotFile::safe(b"externally replaced".to_vec()),
    );
    assert!(registry.apply(binding(2, 'b', 102), 1).is_err());
    assert_eq!(registry.revision().unwrap(), 1);
    assert!(registry.active_bindings().unwrap().is_empty());
}

// Retains the last-good live registry when an atomic reload snapshot cannot commit.
#[test]
fn persistent_registry_reload_is_atomic_with_its_snapshot() {
    let io = Arc::new(MockSnapshotIo::new());
    let registry = Arc::new(
        WatchdogControllerRegistry::open_persistent(
            allowlist('f'),
            1,
            snapshot_provider(io.clone()),
        )
        .unwrap(),
    );
    let store = WatchdogControllerRegistryStore::new(registry.clone());
    let initial_snapshot = io.bytes(SNAPSHOT_PATH);
    let replacement = WatchdogControllerAllowlist::parse(
        format!(
            "version=1\ninstallation_id={}\ncontroller={},{}\n",
            "f".repeat(64),
            "b".repeat(32),
            "2".repeat(64)
        )
        .as_bytes(),
    )
    .unwrap();

    io.fail_replace.store(true, Ordering::Release);
    assert!(store.reload(replacement.clone()).is_err());
    let (generation, retained) = store.current().unwrap();
    assert_eq!(generation, 1);
    assert!(Arc::ptr_eq(&retained, &registry));
    assert_eq!(io.bytes(SNAPSHOT_PATH), initial_snapshot);

    io.fail_replace.store(false, Ordering::Release);
    assert_eq!(store.reload(replacement).unwrap(), 2);
    assert_ne!(io.bytes(SNAPSHOT_PATH), initial_snapshot);
}

// Rebinds only a checksum-valid empty bootstrap after setup trust was rolled back and reissued.
#[test]
fn persistent_registry_rebinds_an_empty_failed_setup_snapshot_only() {
    let io = Arc::new(MockSnapshotIo::new());
    let first = WatchdogControllerRegistry::open_persistent(
        allowlist('f'),
        1,
        snapshot_provider(io.clone()),
    )
    .unwrap();
    let abandoned = first.snapshot().unwrap();

    let replacement = WatchdogControllerRegistry::open_persistent(
        allowlist('e'),
        1,
        snapshot_provider(io.clone()),
    )
    .unwrap();
    assert!(replacement.active_bindings().unwrap().is_empty());
    assert_ne!(replacement.snapshot().unwrap(), abandoned);
    assert_eq!(io.bytes(SNAPSHOT_PATH), replacement.snapshot().unwrap());

    replacement.apply(binding(1, 'a', 101), 1).unwrap();
    assert!(
        WatchdogControllerRegistry::open_persistent(allowlist('f'), 1, snapshot_provider(io),)
            .is_err()
    );
}

// Proves corrupt, foreign, and unsafe snapshot observations fail before registry construction.
#[test]
fn persistent_registry_rejects_corrupt_foreign_and_unsafe_snapshots() {
    let io = Arc::new(MockSnapshotIo::new());
    let registry = WatchdogControllerRegistry::open_persistent(
        allowlist('f'),
        1,
        snapshot_provider(io.clone()),
    )
    .unwrap();
    let valid = registry.snapshot().unwrap();

    let mut corrupt = valid.clone();
    corrupt[10] ^= 1;
    io.replace_external(SNAPSHOT_PATH, MockSnapshotFile::safe(corrupt));
    assert!(WatchdogControllerRegistry::open_persistent(
        allowlist('f'),
        1,
        snapshot_provider(io.clone()),
    )
    .is_err());

    io.replace_external(SNAPSHOT_PATH, MockSnapshotFile::safe(valid.clone()));
    registry.apply(binding(1, 'a', 101), 1).unwrap();
    let active = registry.snapshot().unwrap();
    io.replace_external(SNAPSHOT_PATH, MockSnapshotFile::safe(active));
    assert!(WatchdogControllerRegistry::open_persistent(
        allowlist('e'),
        1,
        snapshot_provider(io.clone()),
    )
    .is_err());

    for unsafe_file in [
        MockSnapshotFile {
            mode: 0o640,
            ..MockSnapshotFile::safe(valid.clone())
        },
        MockSnapshotFile {
            link_count: 2,
            ..MockSnapshotFile::safe(valid.clone())
        },
        MockSnapshotFile {
            is_regular_file: false,
            ..MockSnapshotFile::safe(valid.clone())
        },
    ] {
        io.replace_external(SNAPSHOT_PATH, unsafe_file);
        assert!(WatchdogControllerRegistry::open_persistent(
            allowlist('f'),
            1,
            snapshot_provider(io.clone()),
        )
        .is_err());
    }
}

// Proves system persistence is atomic, private, no-follow, single-link, and restart-safe.
#[test]
fn system_snapshot_persistence_enforces_private_atomic_file_identity() {
    let directory = tempdir().unwrap();
    let canonical_directory = fs::canonicalize(directory.path()).unwrap();
    fs::set_permissions(&canonical_directory, fs::Permissions::from_mode(0o700)).unwrap();
    let path = canonical_directory.join("controller.snapshot");
    let owner_user_id = unsafe { libc::geteuid() };
    let io: Arc<dyn WatchdogControllerSnapshotIo> = Arc::new(SystemWatchdogControllerSnapshotIo);
    let provider = Arc::new(
        FilesystemWatchdogControllerSnapshotProvider::new(path.clone(), owner_user_id, io.clone())
            .unwrap(),
    );
    let registry =
        WatchdogControllerRegistry::open_persistent(allowlist('f'), 1, provider).unwrap();
    registry.apply(binding(1, 'a', 101), 1).unwrap();
    assert_eq!(fs::read(&path).unwrap(), registry.snapshot().unwrap());
    let metadata = fs::symlink_metadata(&path).unwrap();
    assert!(metadata.is_file());
    assert_eq!(metadata.mode() & 0o7777, 0o600);
    assert_eq!(metadata.nlink(), 1);

    let restored = WatchdogControllerRegistry::open_persistent(
        allowlist('f'),
        1,
        Arc::new(
            FilesystemWatchdogControllerSnapshotProvider::new(
                path.clone(),
                owner_user_id,
                io.clone(),
            )
            .unwrap(),
        ),
    )
    .unwrap();
    assert_eq!(restored.active_bindings().unwrap().len(), 1);

    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
    assert!(WatchdogControllerRegistry::open_persistent(
        allowlist('f'),
        1,
        Arc::new(
            FilesystemWatchdogControllerSnapshotProvider::new(
                path.clone(),
                owner_user_id,
                io.clone(),
            )
            .unwrap(),
        ),
    )
    .is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

    let hard_link = canonical_directory.join("controller-hard-link.snapshot");
    fs::hard_link(&path, hard_link).unwrap();
    assert!(WatchdogControllerRegistry::open_persistent(
        allowlist('f'),
        1,
        Arc::new(
            FilesystemWatchdogControllerSnapshotProvider::new(
                path.clone(),
                owner_user_id,
                io.clone(),
            )
            .unwrap(),
        ),
    )
    .is_err());

    let linked_path = canonical_directory.join("controller-linked.snapshot");
    symlink(&path, &linked_path).unwrap();
    assert!(WatchdogControllerRegistry::open_persistent(
        allowlist('f'),
        1,
        Arc::new(
            FilesystemWatchdogControllerSnapshotProvider::new(linked_path, owner_user_id, io,)
                .unwrap(),
        ),
    )
    .is_err());
}

// Creates one provider over the shared deterministic mock filesystem.
fn snapshot_provider(io: Arc<MockSnapshotIo>) -> Arc<FilesystemWatchdogControllerSnapshotProvider> {
    Arc::new(
        FilesystemWatchdogControllerSnapshotProvider::new(PathBuf::from(SNAPSHOT_PATH), 501, io)
            .unwrap(),
    )
}

// Creates one exact single-controller allowlist under the selected installation identity.
fn allowlist(installation: char) -> WatchdogControllerAllowlist {
    WatchdogControllerAllowlist::parse(
        format!(
            "version=1\ninstallation_id={}\ncontroller={},{}\n",
            installation.to_string().repeat(64),
            "a".repeat(32),
            "1".repeat(64),
        )
        .as_bytes(),
    )
    .unwrap()
}

// Creates one exact active controller binding and protected process identity.
fn binding(
    session_generation: u64,
    target_generation: char,
    process_id: u32,
) -> WatchdogControllerBinding {
    WatchdogControllerBinding::new(
        &"a".repeat(32),
        &"1".repeat(64),
        session_generation,
        protected_target(target_generation, process_id),
    )
    .unwrap()
}

// Creates one exact active version-one protection descriptor.
fn protected_target(generation: char, process_id: u32) -> WatchdogProtectedEngine {
    WatchdogProtectedEngine::parse(&format!(
        "version=1\ngeneration={}\nphase=armed\ncontainer_name=container-{generation}\ncontainer_id={}\npid={process_id}\nstart_ticks={}\nboot_id=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\ncgroup=/sys/fs/cgroup/letsinfer/{process_id}\n",
        generation.to_string().repeat(32),
        generation.to_string().repeat(64),
        u64::from(process_id) * 10,
    ))
    .unwrap()
}
