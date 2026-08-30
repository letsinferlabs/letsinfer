// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{HashMap, HashSet};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use li_core_interface::{
    BootId, DeviceId, EndpointOwnership, EntityTimestamps, NetworkInterfaceName, NodeAddress,
    NodeId, Placement, PlacementAssignment, PlacementGroupId, PlacementId, PlacementResources,
    PlacementState, PortRange, RuntimeInstallationId, Sha256Digest, TaskId, TechnicalName,
    UnixMilliseconds,
};
use li_placement_manager::{
    FilesystemLinuxPlacementProtectionProvider, LinuxPlacementProtectedTargetProvider,
    LinuxPlacementProtectionProvider, LinuxProtectedProcessIdentity, LinuxProtectionIo,
    PlacementError, PlacementProtectionGeneration, PlacementProtectionGenerationProvider,
    PlacementProtectionPhase, SystemLinuxProtectionIo, SystemProtectionGenerationProvider,
};

// Returns one exact placement whose protection slot is deterministic.
fn placement() -> Placement {
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
            NodeAddress::parse("spark.local").expect("address"),
            PlacementResources::new(
                PortRange::new(18_000, 2).expect("ports"),
                vec![DeviceId::parse("GPU-A").expect("GPU")],
                Some(NetworkInterfaceName::parse("enp1s0f0np0").expect("RDMA")),
            )
            .expect("resources"),
            EndpointOwnership::Owner,
        ),
        PlacementState::Staged,
        None,
        None,
        EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(1_000))
            .expect("timestamps"),
    )
    .expect("placement")
}

// Returns one process identity whose container name binds the placement exactly.
fn process() -> LinuxProtectedProcessIdentity {
    LinuxProtectedProcessIdentity::new(
        TechnicalName::parse(&format!("li_placement_{}", "1".repeat(32))).expect("name"),
        Sha256Digest::parse(&"5".repeat(64)).expect("container"),
        1_234,
        9_876,
        BootId::parse("11111111-2222-3333-4444-555555555555").expect("boot"),
        "/sys/fs/cgroup/user.slice/user-1000.slice/placement.scope",
    )
    .expect("process")
}

// Returns one field from a descriptor fixture.
fn field(payload: &[u8], key: &str) -> Option<String> {
    std::str::from_utf8(payload).ok()?.lines().find_map(|line| {
        let (candidate, value) = line.split_once('=')?;
        (candidate == key).then(|| value.to_string())
    })
}

// Mocks private filesystem state and Watchdog acknowledgement deterministically.
#[derive(Default)]
struct MockIo {
    directories: Mutex<HashSet<PathBuf>>,
    files: Mutex<HashMap<PathBuf, Vec<u8>>>,
    failures: Mutex<HashSet<String>>,
    auto_acknowledge: AtomicBool,
    malformed_acknowledgement: AtomicBool,
    waits: AtomicUsize,
}

impl MockIo {
    // Creates one mock that acknowledges every valid state write by default.
    fn acknowledging() -> Self {
        Self {
            auto_acknowledge: AtomicBool::new(true),
            ..Self::default()
        }
    }

    // Configures one exact native I/O boundary to fail.
    fn fail(&self, action: &str) {
        self.failures
            .lock()
            .expect("failures")
            .insert(action.to_string());
    }

    // Returns whether one configured native I/O boundary must fail.
    fn should_fail(&self, action: &str) -> bool {
        self.failures.lock().expect("failures").contains(action)
    }

    // Inserts one exact private-file payload.
    fn insert(&self, path: PathBuf, payload: &[u8]) {
        if let Some(parent) = path.parent() {
            self.directories
                .lock()
                .expect("directories")
                .insert(parent.to_path_buf());
        }
        self.files
            .lock()
            .expect("files")
            .insert(path, payload.to_vec());
    }

    // Returns one stored payload for assertions.
    fn payload(&self, path: &Path) -> Vec<u8> {
        self.files
            .lock()
            .expect("files")
            .get(path)
            .expect("payload")
            .clone()
    }

    // Creates the exact Watchdog acknowledgement for one state payload.
    fn acknowledge(&self, state_path: &Path, payload: &[u8]) {
        let acknowledgement_path = state_path.with_file_name("protected-placement.ack");
        let payload = if self.malformed_acknowledgement.load(Ordering::SeqCst) {
            b"malformed\n".to_vec()
        } else {
            format!(
                "version=1\ngeneration={}\nphase={}\ncontainer_id={}\n",
                field(payload, "generation").expect("generation"),
                field(payload, "phase").expect("phase"),
                field(payload, "container_id").expect("container")
            )
            .into_bytes()
        };
        self.insert(acknowledgement_path, &payload);
    }
}

impl LinuxProtectionIo for MockIo {
    // Creates one deterministic private directory or returns the configured failure.
    fn ensure_private_directory(
        &self,
        path: &Path,
        _owner_user_id: u32,
    ) -> Result<(), PlacementError> {
        if self.should_fail("ensure_directory") {
            return Err(PlacementError::ProtectionUnsafe);
        }
        self.directories
            .lock()
            .expect("directories")
            .insert(path.to_path_buf());
        Ok(())
    }

    // Stores one exact payload and optionally synthesizes Watchdog acknowledgement.
    fn write_atomic_private_file(
        &self,
        path: &Path,
        payload: &[u8],
        _owner_user_id: u32,
    ) -> Result<(), PlacementError> {
        if self.should_fail("write") {
            return Err(PlacementError::ProtectionUnsafe);
        }
        self.insert(path.to_path_buf(), payload);
        if path.file_name().and_then(|value| value.to_str()) == Some("protected-placement.state")
            && self.auto_acknowledge.load(Ordering::SeqCst)
        {
            self.acknowledge(path, payload);
        }
        Ok(())
    }

    // Returns one bounded payload or the configured read failure.
    fn read_private_file(
        &self,
        path: &Path,
        maximum_bytes: usize,
        _owner_user_id: u32,
    ) -> Result<Option<Vec<u8>>, PlacementError> {
        if self.should_fail("read") {
            return Err(PlacementError::ProtectionUnsafe);
        }
        let value = self.files.lock().expect("files").get(path).cloned();
        if value
            .as_ref()
            .is_some_and(|payload| payload.len() > maximum_bytes)
        {
            return Err(PlacementError::ProtectionUnsafe);
        }
        Ok(value)
    }

    // Removes one exact file or returns the configured removal failure.
    fn remove_private_file(
        &self,
        path: &Path,
        _owner_user_id: u32,
    ) -> Result<bool, PlacementError> {
        if self.should_fail("remove_file") {
            return Err(PlacementError::ProtectionUnsafe);
        }
        Ok(self.files.lock().expect("files").remove(path).is_some())
    }

    // Removes one empty directory or refuses an unknown retained entry.
    fn remove_private_directory(
        &self,
        path: &Path,
        _owner_user_id: u32,
    ) -> Result<bool, PlacementError> {
        if self.should_fail("remove_directory")
            || self
                .files
                .lock()
                .expect("files")
                .keys()
                .any(|candidate| candidate.parent() == Some(path))
        {
            return Err(PlacementError::ProtectionUnsafe);
        }
        Ok(self.directories.lock().expect("directories").remove(path))
    }

    // Records one deterministic acknowledgement polling interval.
    fn wait(&self, _duration: Duration) {
        self.waits.fetch_add(1, Ordering::SeqCst);
    }
}

// Supplies one deterministic generation and configurable entropy failure.
struct MockGeneration {
    value: String,
    fail: AtomicBool,
}

impl MockGeneration {
    // Creates one deterministic canonical generation provider.
    fn new(character: char) -> Self {
        Self {
            value: character.to_string().repeat(32),
            fail: AtomicBool::new(false),
        }
    }
}

impl PlacementProtectionGenerationProvider for MockGeneration {
    // Returns the configured generation or entropy failure.
    fn generation(&self) -> Result<PlacementProtectionGeneration, PlacementError> {
        if self.fail.load(Ordering::SeqCst) {
            Err(PlacementError::ProtectionUnsafe)
        } else {
            PlacementProtectionGeneration::parse(&self.value)
        }
    }
}

// Groups one filesystem provider and its retained deterministic boundaries.
struct Fixture {
    provider: FilesystemLinuxPlacementProtectionProvider,
    io: Arc<MockIo>,
    generation: Arc<MockGeneration>,
    placement: Placement,
    root: PathBuf,
}

// Creates one automatically acknowledged filesystem protection fixture.
fn fixture() -> Fixture {
    let root = PathBuf::from("/managed/protected-placements");
    let io = Arc::new(MockIo::acknowledging());
    let generation = Arc::new(MockGeneration::new('8'));
    let provider = FilesystemLinuxPlacementProtectionProvider::new(
        root.clone(),
        501,
        3,
        Duration::from_millis(1),
        io.clone(),
        generation.clone(),
    )
    .expect("provider");
    Fixture {
        provider,
        io,
        generation,
        placement: placement(),
        root,
    }
}

// Returns one exact slot path under the fixture root.
fn slot(fixture: &Fixture) -> PathBuf {
    fixture.root.join(fixture.placement.placement_id().as_str())
}

// Rejects noncanonical roots and unbounded acknowledgement configuration.
#[test]
fn provider_rejects_invalid_configuration() {
    let io = Arc::new(MockIo::acknowledging());
    let generation = Arc::new(MockGeneration::new('8'));
    for (root, attempts, interval) in [
        (
            PathBuf::from("relative/protected-placements"),
            3,
            Duration::from_millis(1),
        ),
        (PathBuf::from("/managed/wrong"), 3, Duration::from_millis(1)),
        (
            PathBuf::from("/managed/protected-placements"),
            0,
            Duration::from_millis(1),
        ),
        (
            PathBuf::from("/managed/protected-placements"),
            3,
            Duration::ZERO,
        ),
    ] {
        assert!(FilesystemLinuxPlacementProtectionProvider::new(
            root,
            501,
            attempts,
            interval,
            io.clone(),
            generation.clone(),
        )
        .is_err());
    }
}

// Publishes exact pending bytes after removing stale acknowledgement.
#[test]
fn begin_publishes_and_receives_exact_pending_acknowledgement() {
    let fixture = fixture();
    let acknowledgement = slot(&fixture).join("protected-placement.ack");
    fixture.io.insert(acknowledgement, b"stale\n");
    let generation = fixture.provider.begin(&fixture.placement).expect("begin");
    assert_eq!(generation.as_str(), "8".repeat(32));
    let state = fixture
        .io
        .payload(&slot(&fixture).join("protected-placement.state"));
    assert_eq!(field(&state, "phase").as_deref(), Some("pending"));
    assert_eq!(field(&state, "container_id").as_deref(), Some("-"));
    assert_eq!(
        fixture
            .provider
            .status(&fixture.placement, None)
            .expect("status")
            .phase(),
        PlacementProtectionPhase::Pending
    );
}

// Publishes starting and armed descriptors with the same exact process identity.
#[test]
fn process_binding_and_arming_preserve_complete_identity() {
    let fixture = fixture();
    let generation = fixture.provider.begin(&fixture.placement).expect("begin");
    fixture
        .provider
        .bind_starting(&fixture.placement, &generation, &process())
        .expect("starting");
    fixture
        .provider
        .arm(&fixture.placement, &generation, &process())
        .expect("armed");
    let state = fixture
        .io
        .payload(&slot(&fixture).join("protected-placement.state"));
    assert_eq!(field(&state, "phase").as_deref(), Some("armed"));
    assert_eq!(
        field(&state, "container_id").as_deref(),
        Some("5555555555555555555555555555555555555555555555555555555555555555")
    );
    assert_eq!(field(&state, "pid").as_deref(), Some("1234"));
    assert_eq!(field(&state, "start_ticks").as_deref(), Some("9876"));
    assert_eq!(
        field(&state, "boot_id").as_deref(),
        Some("11111111-2222-3333-4444-555555555555")
    );
    assert_eq!(
        field(&state, "cgroup").as_deref(),
        Some("/sys/fs/cgroup/user.slice/user-1000.slice/placement.scope")
    );
    assert_eq!(
        fixture
            .provider
            .status(&fixture.placement, Some(&process()))
            .expect("status")
            .phase(),
        PlacementProtectionPhase::Armed
    );
}

// Exposes only the exact acknowledged active descriptor and retires it after disarm.
#[test]
fn active_target_preserves_generation_phase_and_process_identity() {
    let fixture = fixture();
    let generation = fixture.provider.begin(&fixture.placement).expect("begin");
    fixture
        .provider
        .arm(&fixture.placement, &generation, &process())
        .expect("armed");
    let target = fixture
        .provider
        .active_target(&fixture.placement)
        .expect("target")
        .expect("active target");
    assert_eq!(target.generation(), &generation);
    assert_eq!(target.phase(), PlacementProtectionPhase::Armed);
    assert_eq!(target.process(), &process());

    fixture.provider.disarm(&fixture.placement).expect("disarm");
    assert!(fixture
        .provider
        .active_target(&fixture.placement)
        .expect("inactive target")
        .is_none());
}

// Rejects a process whose managed container name differs from the placement.
#[test]
fn process_binding_rejects_foreign_container_name() {
    let fixture = fixture();
    let generation = fixture.provider.begin(&fixture.placement).expect("begin");
    let foreign = LinuxProtectedProcessIdentity::new(
        TechnicalName::parse("li_placement_foreign").expect("name"),
        Sha256Digest::parse(&"5".repeat(64)).expect("container"),
        1_234,
        9_876,
        BootId::parse("11111111-2222-3333-4444-555555555555").expect("boot"),
        "/sys/fs/cgroup/user.slice/user-1000.slice/placement.scope",
    )
    .expect("process");
    assert_eq!(
        fixture
            .provider
            .bind_starting(&fixture.placement, &generation, &foreign)
            .expect_err("foreign name"),
        PlacementError::ProtectionUnsafe
    );
}

// Rejects a durable trip before writing pending or consuming a generation.
#[test]
fn begin_never_overwrites_a_durable_trip() {
    let fixture = fixture();
    fixture.io.insert(
        slot(&fixture).join("protection-trip.json"),
        br#"{"reason":"oom"}"#,
    );
    assert_eq!(
        fixture
            .provider
            .begin(&fixture.placement)
            .expect_err("trip"),
        PlacementError::ProtectionUnsafe
    );
    assert!(!fixture
        .io
        .files
        .lock()
        .expect("files")
        .contains_key(&slot(&fixture).join("protected-placement.state")));
}

// Times out on absent or malformed acknowledgement after exact bounded polling.
#[test]
fn acknowledgement_wait_is_bounded_and_fail_closed() {
    for malformed in [false, true] {
        let fixture = fixture();
        fixture
            .io
            .auto_acknowledge
            .store(malformed, Ordering::SeqCst);
        fixture
            .io
            .malformed_acknowledgement
            .store(malformed, Ordering::SeqCst);
        assert_eq!(
            fixture
                .provider
                .begin(&fixture.placement)
                .expect_err("timeout"),
            PlacementError::ProtectionUnsafe
        );
        assert_eq!(fixture.io.waits.load(Ordering::SeqCst), 2);
    }
}

// Rejects corrupt descriptors, mismatched acknowledgements, and foreign live identity.
#[test]
fn status_fails_closed_on_every_semantic_mismatch() {
    let descriptor = fixture();
    descriptor
        .provider
        .begin(&descriptor.placement)
        .expect("begin");
    descriptor.io.insert(
        slot(&descriptor).join("protected-placement.state"),
        b"version=1\ngeneration=88888888888888888888888888888888\nphase=invalid\ncontainer_name=li_placement_11111111111111111111111111111111\ncontainer_id=-\npid=-\nstart_ticks=-\nboot_id=-\ncgroup=-\n",
    );
    assert_eq!(
        descriptor
            .provider
            .status(&descriptor.placement, None)
            .expect_err("invalid descriptor"),
        PlacementError::ProtectionUnsafe
    );

    let acknowledgement = fixture();
    acknowledgement
        .provider
        .begin(&acknowledgement.placement)
        .expect("begin");
    acknowledgement.io.insert(
        slot(&acknowledgement).join("protected-placement.ack"),
        b"version=1\ngeneration=99999999999999999999999999999999\nphase=pending\ncontainer_id=-\n",
    );
    assert_eq!(
        acknowledgement
            .provider
            .status(&acknowledgement.placement, None)
            .expect_err("mismatched acknowledgement"),
        PlacementError::ProtectionUnsafe
    );

    let identity = fixture();
    let generation = identity.provider.begin(&identity.placement).expect("begin");
    identity
        .provider
        .bind_starting(&identity.placement, &generation, &process())
        .expect("starting");
    let foreign = LinuxProtectedProcessIdentity::new(
        TechnicalName::parse(&format!("li_placement_{}", "1".repeat(32))).expect("name"),
        Sha256Digest::parse(&"6".repeat(64)).expect("container"),
        1_234,
        9_876,
        BootId::parse("11111111-2222-3333-4444-555555555555").expect("boot"),
        "/sys/fs/cgroup/user.slice/user-1000.slice/placement.scope",
    )
    .expect("foreign process");
    assert_eq!(
        identity
            .provider
            .status(&identity.placement, Some(&foreign))
            .expect_err("foreign identity"),
        PlacementError::ProtectionUnsafe
    );
}

// Reuses one existing generation when publishing acknowledged disarm.
#[test]
fn disarm_reuses_generation_and_removes_process_identity() {
    let fixture = fixture();
    let generation = fixture.provider.begin(&fixture.placement).expect("begin");
    fixture
        .provider
        .bind_starting(&fixture.placement, &generation, &process())
        .expect("starting");
    let status = fixture.provider.disarm(&fixture.placement).expect("disarm");
    assert_eq!(status.phase(), PlacementProtectionPhase::Disarmed);
    let state = fixture
        .io
        .payload(&slot(&fixture).join("protected-placement.state"));
    assert_eq!(
        field(&state, "generation").as_deref(),
        Some(generation.as_str())
    );
    assert_eq!(field(&state, "container_id").as_deref(), Some("-"));
}

// Clears exactly one private trip without changing descriptor or acknowledgement.
#[test]
fn trip_acknowledgement_removes_only_the_trip_file() {
    let fixture = fixture();
    fixture.provider.begin(&fixture.placement).expect("begin");
    let state_path = slot(&fixture).join("protected-placement.state");
    let state = fixture.io.payload(&state_path);
    let trip_path = slot(&fixture).join("protection-trip.json");
    fixture.io.insert(trip_path.clone(), b"{}\n");
    assert!(fixture
        .provider
        .acknowledge_trip(&fixture.placement)
        .expect("acknowledge"));
    assert!(!fixture
        .provider
        .acknowledge_trip(&fixture.placement)
        .expect("replayed acknowledgement"));
    assert_eq!(fixture.io.payload(&state_path), state);
    assert!(!fixture
        .io
        .files
        .lock()
        .expect("files")
        .contains_key(&trip_path));
}

// Retires only one disarmed, trip-free, otherwise empty exact slot.
#[test]
fn retirement_requires_disarmed_empty_slot() {
    let completed = fixture();
    completed
        .provider
        .disarm(&completed.placement)
        .expect("disarm");
    completed
        .provider
        .retire(&completed.placement)
        .expect("retire");
    assert!(!completed
        .io
        .directories
        .lock()
        .expect("directories")
        .contains(&slot(&completed)));

    let unknown = fixture();
    unknown.provider.disarm(&unknown.placement).expect("disarm");
    unknown.io.insert(slot(&unknown).join("foreign"), b"data");
    assert_eq!(
        unknown
            .provider
            .retire(&unknown.placement)
            .expect_err("unknown file"),
        PlacementError::ProtectionUnsafe
    );

    let armed = fixture();
    let generation = armed.provider.begin(&armed.placement).expect("begin");
    armed
        .provider
        .arm(&armed.placement, &generation, &process())
        .expect("armed");
    assert_eq!(
        armed.provider.retire(&armed.placement).expect_err("armed"),
        PlacementError::ProtectionUnsafe
    );
}

// Propagates every injected filesystem and generation failure without fallback.
#[test]
fn provider_fails_at_each_injected_native_boundary() {
    for boundary in ["ensure_directory", "read", "remove_file", "write"] {
        let fixture = fixture();
        fixture.io.fail(boundary);
        assert!(
            fixture.provider.begin(&fixture.placement).is_err(),
            "{boundary}"
        );
    }
    let generation = fixture();
    generation.generation.fail.store(true, Ordering::SeqCst);
    assert_eq!(
        generation
            .provider
            .begin(&generation.placement)
            .expect_err("generation"),
        PlacementError::ProtectionUnsafe
    );
    let directory = fixture();
    directory
        .provider
        .disarm(&directory.placement)
        .expect("disarm");
    directory.io.fail("remove_directory");
    assert_eq!(
        directory
            .provider
            .retire(&directory.placement)
            .expect_err("directory"),
        PlacementError::ProtectionUnsafe
    );
}

// System I/O enforces private modes, bounded reads, no-follow paths, and exact cleanup.
#[test]
fn system_io_enforces_private_filesystem_contract() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let owner_user_id = fs::metadata(directory.path()).expect("metadata").uid();
    let root = directory.path().join("protected-placements");
    let io = SystemLinuxProtectionIo::default();
    io.ensure_private_directory(&root, owner_user_id)
        .expect("private directory");
    assert_eq!(
        fs::metadata(&root).expect("metadata").permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        io.ensure_private_directory(&root, owner_user_id.wrapping_add(1))
            .expect_err("foreign owner"),
        PlacementError::ProtectionUnsafe
    );
    let directory_link = directory.path().join("protected-link");
    std::os::unix::fs::symlink(&root, &directory_link).expect("directory symlink");
    assert_eq!(
        io.ensure_private_directory(&directory_link, owner_user_id)
            .expect_err("directory symlink"),
        PlacementError::ProtectionUnsafe
    );
    let state = root.join("state");
    io.write_atomic_private_file(&state, b"private\n", owner_user_id)
        .expect("write");
    assert_eq!(
        io.read_private_file(&state, 32, owner_user_id)
            .expect("read")
            .expect("payload"),
        b"private\n"
    );
    assert_eq!(
        io.read_private_file(&state, 3, owner_user_id)
            .expect_err("bounded read"),
        PlacementError::ProtectionUnsafe
    );
    fs::set_permissions(&state, fs::Permissions::from_mode(0o644)).expect("permissions");
    assert_eq!(
        io.read_private_file(&state, 32, owner_user_id)
            .expect_err("public file"),
        PlacementError::ProtectionUnsafe
    );
    fs::set_permissions(&state, fs::Permissions::from_mode(0o600)).expect("permissions");
    let link = root.join("link");
    std::os::unix::fs::symlink(&state, &link).expect("symlink");
    assert_eq!(
        io.read_private_file(&link, 32, owner_user_id)
            .expect_err("symlink"),
        PlacementError::ProtectionUnsafe
    );
    fs::remove_file(&link).expect("remove symlink");
    assert!(io
        .remove_private_file(&state, owner_user_id)
        .expect("remove file"));
    assert!(io
        .remove_private_directory(&root, owner_user_id)
        .expect("remove directory"));
}

// System generation supplies canonical distinct 128-bit identities.
#[test]
fn system_generation_is_canonical_and_nonrepeating() {
    let provider = SystemProtectionGenerationProvider;
    let first = provider.generation().expect("first generation");
    let second = provider.generation().expect("second generation");
    assert_eq!(first.as_str().len(), 32);
    assert_ne!(first, second);
}
