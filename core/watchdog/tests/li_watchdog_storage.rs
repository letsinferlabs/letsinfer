// SPDX-License-Identifier: AGPL-3.0-only

use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::{symlink, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::{Arc, Mutex};

use li_watchdog_manager::{
    decode_watchdog_record, encode_watchdog_record, FilesystemWatchdogStorage, WatchdogError,
    WatchdogManager, WatchdogProcessState, WatchdogProtectedEngine, WatchdogProtectionObservation,
    WatchdogProtectionProvider, WatchdogResolution, WatchdogRing, WatchdogRingFile,
    WatchdogRingLayout, WatchdogRollup, WatchdogSafetyAction, WatchdogSafetyInput,
    WatchdogSafetyThresholds, WatchdogSample, WatchdogSampleProvider, WatchdogSampleTelemetry,
    WatchdogStorageLayout, WatchdogStorageProvider, WATCHDOG_CLOCK_UNKNOWN,
    WATCHDOG_PERCENT_UNKNOWN, WATCHDOG_RECORD_BYTES, WATCHDOG_SAMPLE_ROLLUP, WATCHDOG_TEMP_UNKNOWN,
};
use tempfile::TempDir;

const ARMED_DESCRIPTOR: &str = "version=1\
\ngeneration=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
\nphase=armed\
\ncontainer_name=li_engine\
\ncontainer_id=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\
\npid=1234\
\nstart_ticks=5678\
\nboot_id=12345678-1234-1234-1234-123456789abc\
\ncgroup=/sys/fs/cgroup/user.slice/li_engine\n";

// Holds deterministic fixed-offset bytes and fault controls for ring tests.
#[derive(Default)]
struct RingFileState {
    bytes: Vec<u8>,
    write_budget: Option<usize>,
    return_zero_on_write: bool,
    synchronization_failures: usize,
    synchronization_count: usize,
}

// Provides partial, torn, corrupt, and failed ring I/O without native timing.
struct RingFileMock {
    maximum_chunk: usize,
    state: Mutex<RingFileState>,
}

impl RingFileMock {
    // Creates one empty mock whose individual reads and writes remain bounded.
    fn new(maximum_chunk: usize) -> Self {
        Self {
            maximum_chunk,
            state: Mutex::new(RingFileState::default()),
        }
    }

    // Restricts all future writes to one total byte budget before failing.
    fn set_write_budget(&self, budget: Option<usize>) {
        self.state.lock().unwrap().write_budget = budget;
    }

    // Selects whether the next write boundary reports no progress.
    fn set_zero_write(&self, enabled: bool) {
        self.state.lock().unwrap().return_zero_on_write = enabled;
    }

    // Configures a deterministic number of synchronization failures.
    fn set_synchronization_failures(&self, failures: usize) {
        self.state.lock().unwrap().synchronization_failures = failures;
    }

    // Replaces one exact byte range to model corruption or a misplaced valid record.
    fn replace(&self, offset: usize, input: &[u8]) {
        let mut state = self.state.lock().unwrap();
        state.bytes[offset..offset + input.len()].copy_from_slice(input);
    }

    // Flips one retained byte without repairing the record CRC.
    fn corrupt(&self, offset: usize) {
        self.state.lock().unwrap().bytes[offset] ^= 1;
    }

    // Returns the number of successful explicit synchronization calls.
    fn synchronization_count(&self) -> usize {
        self.state.lock().unwrap().synchronization_count
    }
}

impl WatchdogRingFile for RingFileMock {
    // Returns the current injected extent.
    fn length(&self) -> Result<u64, WatchdogError> {
        Ok(self.state.lock().unwrap().bytes.len() as u64)
    }

    // Resizes the injected extent exactly like one regular ring file.
    fn set_length(&self, length: u64) -> Result<(), WatchdogError> {
        let length = usize::try_from(length)
            .map_err(|_| WatchdogError::provider("test", "length exceeds platform"))?;
        self.state.lock().unwrap().bytes.resize(length, 0);
        Ok(())
    }

    // Returns at most the configured partial-read size from one exact offset.
    fn read_at(&self, offset: u64, output: &mut [u8]) -> Result<usize, WatchdogError> {
        let offset = usize::try_from(offset)
            .map_err(|_| WatchdogError::provider("test", "offset exceeds platform"))?;
        let state = self.state.lock().unwrap();
        if offset >= state.bytes.len() {
            return Ok(0);
        }
        let count = output
            .len()
            .min(self.maximum_chunk)
            .min(state.bytes.len() - offset);
        output[..count].copy_from_slice(&state.bytes[offset..offset + count]);
        Ok(count)
    }

    // Performs one partial write or the configured torn/no-progress failure.
    fn write_at(&self, offset: u64, input: &[u8]) -> Result<usize, WatchdogError> {
        let offset = usize::try_from(offset)
            .map_err(|_| WatchdogError::provider("test", "offset exceeds platform"))?;
        let mut state = self.state.lock().unwrap();
        if state.return_zero_on_write {
            return Ok(0);
        }
        let budget = state.write_budget.unwrap_or(usize::MAX);
        if budget == 0 {
            return Err(WatchdogError::provider("test", "injected torn write"));
        }
        if offset >= state.bytes.len() {
            return Err(WatchdogError::provider("test", "write exceeds extent"));
        }
        let count = input
            .len()
            .min(self.maximum_chunk)
            .min(state.bytes.len() - offset)
            .min(budget);
        state.bytes[offset..offset + count].copy_from_slice(&input[..count]);
        if let Some(remaining) = &mut state.write_budget {
            *remaining -= count;
        }
        Ok(count)
    }

    // Records one synchronization or returns its injected failure.
    fn synchronize(&self) -> Result<(), WatchdogError> {
        let mut state = self.state.lock().unwrap();
        if state.synchronization_failures > 0 {
            state.synchronization_failures -= 1;
            return Err(WatchdogError::provider("test", "injected sync failure"));
        }
        state.synchronization_count += 1;
        Ok(())
    }
}

// Produces manager samples after the storage head without observing the host.
struct SampleProviderMock;

impl WatchdogSampleProvider for SampleProviderMock {
    // Derives stable clocks and telemetry from the requested sequence.
    fn sample(&self, sequence: u64) -> Result<WatchdogSample, WatchdogError> {
        telemetry_sample(sequence, 300_000 + sequence * 1_000, 70)
    }
}

// Produces one stable low-memory observation and rejects unexpected containment.
struct WarningProtectionMock;

impl WatchdogProtectionProvider for WarningProtectionMock {
    // Returns one exact protected target that should emit a warning only.
    fn observations(
        &self,
        _sample: &WatchdogSample,
    ) -> Result<Vec<WatchdogProtectionObservation>, WatchdogError> {
        Ok(vec![WatchdogProtectionObservation::new(
            WatchdogProtectedEngine::parse(ARMED_DESCRIPTOR)?,
            WatchdogProcessState::Running,
            WatchdogSafetyInput {
                available_bytes: 8 << 30,
                ..WatchdogSafetyInput::default()
            },
            false,
        )])
    }

    // Rejects a disarm acknowledgment because this fixture stays armed.
    fn acknowledge_disarmed(&self, _target: &WatchdogProtectedEngine) -> Result<(), WatchdogError> {
        Err(WatchdogError::provider("test", "unexpected disarm"))
    }

    // Rejects a trip latch because memory pressure is telemetry-only.
    fn latch_trip(
        &self,
        _target: &WatchdogProtectedEngine,
        _action: WatchdogSafetyAction,
        _reason: &'static str,
        _input: WatchdogSafetyInput,
    ) -> Result<(), WatchdogError> {
        Err(WatchdogError::provider("test", "unexpected trip"))
    }

    // Rejects containment because the warning path is non-destructive.
    fn contain(
        &self,
        _target: &WatchdogProtectedEngine,
        _action: WatchdogSafetyAction,
        _grace_milliseconds: u32,
    ) -> Result<bool, WatchdogError> {
        Err(WatchdogError::provider("test", "unexpected containment"))
    }
}

// Decodes the checked-in C fixture without adding a second hexadecimal dependency.
fn c_record_fixture() -> [u8; WATCHDOG_RECORD_BYTES] {
    let value = include_str!("fixtures/li_watchdog_record_v2_c.hex").trim();
    assert_eq!(value.len(), WATCHDOG_RECORD_BYTES * 2);
    let mut output = [0_u8; WATCHDOG_RECORD_BYTES];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hexadecimal_nibble(pair[0]) << 4) | hexadecimal_nibble(pair[1]);
    }
    output
}

// Converts one fixture hexadecimal digit into its exact binary nibble.
fn hexadecimal_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => panic!("fixture contains non-hexadecimal text"),
    }
}

// Creates one fully populated sample while keeping its values easy to average.
fn telemetry_sample(
    sequence: u64,
    unix_milliseconds: u64,
    cpu_percent: u8,
) -> Result<WatchdogSample, WatchdogError> {
    let mut telemetry = WatchdogSampleTelemetry {
        cpu_core_count: 2,
        flags: 0b1010,
        cpu_percent,
        gpu_percent: cpu_percent.saturating_add(10),
        memory_percent: 60,
        disk_percent: 30,
        gpu_memory_percent: 80,
        workload_type: 2,
        system_temp_deci_c: 500 + sequence as i16,
        gpu_temp_deci_c: 600 + sequence as i16,
        nvme_temp_deci_c: WATCHDOG_TEMP_UNKNOWN,
        power_deci_w: 250,
        load1_centi: 150,
        memory_used_mib: 1_000 + sequence as u32,
        memory_total_mib: 2_000,
        disk_used_mib: 3_000 + sequence as u32,
        disk_total_mib: 4_000,
        network_rx_kib_s: 5_000,
        network_tx_kib_s: 6_000,
        disk_read_kib_s: 7_000,
        disk_write_kib_s: 8_000,
        workload_id: 9,
        cpu_clock_mhz: 2_000,
        gpu_clock_mhz: 1_000,
        vram_clock_mhz: WATCHDOG_CLOCK_UNKNOWN,
        system_ram_clock_mhz: WATCHDOG_CLOCK_UNKNOWN,
        active_requests: sequence as u32,
        queued_requests: 2,
        connected_clients: 3,
        requests_received: sequence * 10,
        requests_admitted: sequence * 9,
        requests_completed: sequence * 8,
        output_tokens: sequence * 100,
        ..WatchdogSampleTelemetry::default()
    };
    telemetry.cpu_core_percent[..2].copy_from_slice(&[cpu_percent, cpu_percent]);
    telemetry.gpu_engine_percent[0] = cpu_percent;
    WatchdogSample::with_telemetry(sequence, unix_milliseconds, 10_000 + sequence, telemetry)
}

// Creates one directory with the exact native Watchdog ownership mode.
fn create_storage_directory(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

// Creates one exact-mode regular file for unsafe-path test arrangements.
fn create_storage_file(path: &Path) -> File {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap()
}

// Returns the deterministic manager threshold fixture used by event replay tests.
fn thresholds() -> WatchdogSafetyThresholds {
    WatchdogSafetyThresholds::new(
        16 << 30,
        8 << 30,
        4 << 30,
        1 << 30,
        500_000,
        100_000,
        3,
        5_000,
    )
    .unwrap()
}

// Proves Rust reads and reproduces every byte emitted by the checked-in C encoder.
#[test]
fn record_v2_is_byte_exact_with_the_c_fixture_and_crc() {
    let fixture = c_record_fixture();
    let sample = decode_watchdog_record(&fixture).unwrap();

    assert_eq!(sample.sequence(), 42);
    assert_eq!(sample.unix_milliseconds(), 1_700_000_000_123);
    assert_eq!(sample.monotonic_milliseconds(), 123_456);
    assert_eq!(sample.telemetry().cpu_core_count, 20);
    assert_eq!(sample.telemetry().cpu_percent, 73);
    assert_eq!(sample.telemetry().connected_clients, 6);
    assert_eq!(encode_watchdog_record(&sample).unwrap(), fixture);

    let mut damaged = fixture;
    damaged[148] ^= 1;
    assert!(decode_watchdog_record(&damaged).is_err());
    assert!(decode_watchdog_record(&fixture[..WATCHDOG_RECORD_BYTES - 1]).is_err());
}

// Proves partial I/O completes, wraps create explicit gaps, and corrupt slots stay isolated.
#[test]
fn ring_handles_partial_io_wrap_gaps_corruption_and_bounded_queries() {
    let file = Arc::new(RingFileMock::new(7));
    let layout = WatchdogRingLayout::new(1_000, 4).unwrap();
    let ring = WatchdogRing::with_file(layout, file.clone()).unwrap();
    for sequence in 1..=6 {
        ring.write(&telemetry_sample(sequence, sequence * 1_000, 20).unwrap())
            .unwrap();
    }
    ring.synchronize().unwrap();

    let overwritten = ring.query(1_000, 4_000, 4).unwrap();
    assert_eq!(
        overwritten
            .samples()
            .iter()
            .map(WatchdogSample::sequence)
            .collect::<Vec<_>>(),
        [3, 4]
    );
    assert_eq!(overwritten.missing_buckets(), [1, 2]);
    assert_eq!(ring.latest().unwrap().unwrap().sequence(), 6);
    assert_eq!(file.synchronization_count(), 1);

    let fourth_slot = (4 % layout.capacity()) as usize * WATCHDOG_RECORD_BYTES;
    file.corrupt(fourth_slot + 148);
    assert!(ring.read_bucket(4).unwrap().is_none());
    assert_eq!(ring.latest().unwrap().unwrap().sequence(), 6);

    let misplaced = encode_watchdog_record(&telemetry_sample(99, 9_000, 20).unwrap()).unwrap();
    file.replace(0, &misplaced);
    assert_eq!(ring.latest().unwrap().unwrap().sequence(), 6);
    assert!(ring.query(0, 4_000, 4).is_err());
    assert!(WatchdogRingLayout::new(0, 1).is_err());

    let oversized = Arc::new(RingFileMock::new(7));
    oversized
        .set_length(layout.capacity() * WATCHDOG_RECORD_BYTES as u64 + 1)
        .unwrap();
    assert!(WatchdogRing::with_file(layout, oversized).is_err());
}

// Proves torn, no-progress, and synchronization failures never appear as valid records.
#[test]
fn ring_faults_fail_closed_without_promoting_torn_records() {
    let file = Arc::new(RingFileMock::new(11));
    let ring =
        WatchdogRing::with_file(WatchdogRingLayout::new(1_000, 2).unwrap(), file.clone()).unwrap();
    file.set_write_budget(Some(100));
    assert!(ring
        .write(&telemetry_sample(1, 1_000, 20).unwrap())
        .is_err());
    assert!(ring.read_bucket(1).unwrap().is_none());

    file.set_write_budget(None);
    file.set_zero_write(true);
    assert!(ring
        .write(&telemetry_sample(1, 1_000, 20).unwrap())
        .is_err());
    file.set_zero_write(false);
    ring.write(&telemetry_sample(1, 1_000, 20).unwrap())
        .unwrap();

    file.set_synchronization_failures(1);
    assert!(ring.synchronize().is_err());
    ring.synchronize().unwrap();
    assert_eq!(file.synchronization_count(), 1);
}

// Proves Rust retains the C rollup's averages, sentinels, counters, and rotation time.
#[test]
fn rollup_matches_the_c_average_and_rotation_contract() {
    let mut first = telemetry_sample(1, 120_000, 20).unwrap();
    let mut second = telemetry_sample(2, 150_000, 40).unwrap();
    let next = telemetry_sample(3, 180_000, 60).unwrap();
    let mut first_telemetry = first.telemetry().clone();
    first_telemetry.gpu_percent = WATCHDOG_PERCENT_UNKNOWN;
    first_telemetry.cpu_clock_mhz = WATCHDOG_CLOCK_UNKNOWN;
    first = WatchdogSample::with_telemetry(1, 120_000, 10_001, first_telemetry).unwrap();
    let mut second_telemetry = second.telemetry().clone();
    second_telemetry.system_temp_deci_c = WATCHDOG_TEMP_UNKNOWN;
    second = WatchdogSample::with_telemetry(2, 150_000, 10_002, second_telemetry).unwrap();

    let mut rollup = WatchdogRollup::new(60_000).unwrap();
    assert!(rollup.push(&first).is_none());
    assert!(rollup.push(&second).is_none());
    let completed = rollup.push(&next).unwrap();

    assert_eq!(completed.sequence(), 2);
    assert_eq!(completed.unix_milliseconds(), 120_000);
    assert_eq!(completed.monotonic_milliseconds(), 10_002);
    assert_ne!(completed.telemetry().flags & WATCHDOG_SAMPLE_ROLLUP, 0);
    assert_eq!(completed.telemetry().cpu_percent, 30);
    assert_eq!(completed.telemetry().gpu_percent, 50);
    assert_eq!(completed.telemetry().system_temp_deci_c, 501);
    assert_eq!(completed.telemetry().cpu_clock_mhz, 2_000);
    assert_eq!(completed.telemetry().vram_clock_mhz, WATCHDOG_CLOCK_UNKNOWN);
    assert_eq!(completed.telemetry().requests_completed, 16);
    assert_eq!(completed.telemetry().output_tokens, 200);
    assert_eq!(rollup.complete_partial().unwrap().sequence(), 3);
    assert!(rollup.complete_partial().is_none());
    assert!(WatchdogRollup::new(0).is_err());
}

// Proves restart rebuilds partial rollups and preserves sample and safety-event identity.
#[test]
fn filesystem_storage_recovers_rollups_and_replays_exactly() {
    let temporary = TempDir::new().unwrap();
    let root = temporary.path().join("watchdog");
    let layout = WatchdogStorageLayout::new(64, 4, 4).unwrap();
    let storage = FilesystemWatchdogStorage::open_with_layout(&root, layout).unwrap();
    let first = telemetry_sample(1, 120_000, 10).unwrap();
    let second = telemetry_sample(2, 150_000, 30).unwrap();
    let third = telemetry_sample(3, 180_000, 30).unwrap();
    storage.record_sample(&first).unwrap();
    storage.record_sample(&second).unwrap();
    storage.record_sample(&third).unwrap();

    storage.flush().unwrap();
    drop(storage);

    let storage = Arc::new(FilesystemWatchdogStorage::open_with_layout(&root, layout).unwrap());
    assert_eq!(storage.next_sequence().unwrap(), 4);
    storage.record_sample(&third).unwrap();
    let conflict = telemetry_sample(3, 180_000, 31).unwrap();
    assert!(storage.record_sample(&conflict).is_err());
    storage
        .record_sample(&telemetry_sample(4, 210_000, 50).unwrap())
        .unwrap();
    storage
        .record_sample(&telemetry_sample(5, 240_000, 70).unwrap())
        .unwrap();
    let manager = WatchdogManager::new(
        thresholds(),
        Arc::new(SampleProviderMock),
        Arc::new(WarningProtectionMock),
        storage.clone(),
    )
    .unwrap();
    let tick = manager.tick().unwrap();
    assert_eq!(tick.events().len(), 1);
    storage.flush().unwrap();
    let event_path = root.join("events.ring");
    let first_event_bytes = fs::read(&event_path).unwrap();
    storage.record_event(&tick.events()[0]).unwrap();
    storage.flush().unwrap();
    assert_eq!(fs::read(&event_path).unwrap(), first_event_bytes);
    drop(manager);
    drop(storage);

    let storage = FilesystemWatchdogStorage::open_with_layout(&root, layout).unwrap();
    storage.record_event(&tick.events()[0]).unwrap();
    storage.flush().unwrap();
    assert_eq!(fs::read(&event_path).unwrap(), first_event_bytes);

    let minute = storage
        .history(WatchdogResolution::Minute, 120_000, 240_000, 4)
        .unwrap();
    assert_eq!(minute.samples().len(), 3);
    assert_eq!(minute.samples()[0].sequence(), 2);
    assert_eq!(minute.samples()[0].telemetry().cpu_percent, 20);
    assert_eq!(minute.samples()[1].sequence(), 4);
    assert_eq!(minute.samples()[1].telemetry().cpu_percent, 40);
    assert_eq!(minute.samples()[2].sequence(), 5);
    assert_eq!(minute.samples()[2].telemetry().cpu_percent, 70);
    assert!(minute.missing_buckets().is_empty());

    assert_eq!(fs::metadata(root.join("raw.ring")).unwrap().len(), 64 * 284);
    assert_eq!(
        fs::metadata(root.join("minute.ring")).unwrap().len(),
        4 * 284
    );
    assert_eq!(
        fs::metadata(root.join("quarter-hour.ring")).unwrap().len(),
        4 * 284
    );
    assert_eq!(fs::metadata(event_path).unwrap().len(), 65 * 64);
    assert!(!root.join("metadata.sqlite3").exists());
}

// Proves nonzero corrupt safety-event bytes fail restart without being silently rewritten.
#[test]
fn safety_event_journal_corruption_fails_closed_without_rewriting() {
    let temporary = TempDir::new().unwrap();
    let root = temporary.path().join("watchdog");
    let layout = WatchdogStorageLayout::new(4, 2, 2).unwrap();
    let storage = FilesystemWatchdogStorage::open_with_layout(&root, layout).unwrap();
    let manager = WatchdogManager::new(
        thresholds(),
        Arc::new(SampleProviderMock),
        Arc::new(WarningProtectionMock),
        Arc::new(storage),
    )
    .unwrap();
    manager.tick().unwrap();
    manager.flush().unwrap();
    drop(manager);

    let path = root.join("events.ring");
    let mut corrupt = fs::read(&path).unwrap();
    corrupt[28] ^= 1;
    fs::write(&path, &corrupt).unwrap();
    let retained = fs::read(&path).unwrap();
    assert!(FilesystemWatchdogStorage::open_with_layout(&root, layout).is_err());
    assert_eq!(fs::read(path).unwrap(), retained);
}

// Proves final-component symlinks, hard links, and permissive modes fail closed.
#[test]
fn native_storage_rejects_unsafe_paths_modes_and_links() {
    let temporary = TempDir::new().unwrap();
    let layout = WatchdogStorageLayout::new(4, 2, 2).unwrap();

    let actual = temporary.path().join("actual");
    create_storage_directory(&actual);
    let linked_root = temporary.path().join("linked");
    symlink(&actual, &linked_root).unwrap();
    assert!(FilesystemWatchdogStorage::open_with_layout(&linked_root, layout).is_err());

    let permissive = temporary.path().join("permissive");
    create_storage_directory(&permissive);
    fs::set_permissions(&permissive, fs::Permissions::from_mode(0o770)).unwrap();
    assert!(FilesystemWatchdogStorage::open_with_layout(&permissive, layout).is_err());

    let group_readable = temporary.path().join("group-readable");
    create_storage_directory(&group_readable);
    fs::set_permissions(&group_readable, fs::Permissions::from_mode(0o750)).unwrap();
    assert!(FilesystemWatchdogStorage::open_with_layout(&group_readable, layout).is_err());

    let hard_linked = temporary.path().join("hard-linked");
    create_storage_directory(&hard_linked);
    let raw = hard_linked.join("raw.ring");
    drop(create_storage_file(&raw));
    fs::hard_link(&raw, hard_linked.join("alias.ring")).unwrap();
    assert!(FilesystemWatchdogStorage::open_with_layout(&hard_linked, layout).is_err());

    let wrong_mode = temporary.path().join("wrong-mode");
    create_storage_directory(&wrong_mode);
    let raw = wrong_mode.join("raw.ring");
    drop(create_storage_file(&raw));
    fs::set_permissions(&raw, fs::Permissions::from_mode(0o660)).unwrap();
    assert!(FilesystemWatchdogStorage::open_with_layout(&wrong_mode, layout).is_err());

    let group_readable_file = temporary.path().join("group-readable-file");
    create_storage_directory(&group_readable_file);
    let raw = group_readable_file.join("raw.ring");
    drop(create_storage_file(&raw));
    fs::set_permissions(&raw, fs::Permissions::from_mode(0o640)).unwrap();
    assert!(FilesystemWatchdogStorage::open_with_layout(&group_readable_file, layout).is_err());

    let linked_events = temporary.path().join("linked-events");
    create_storage_directory(&linked_events);
    let event_target = linked_events.join("event-target");
    drop(create_storage_file(&event_target));
    symlink(&event_target, linked_events.join("events.ring")).unwrap();
    assert!(FilesystemWatchdogStorage::open_with_layout(&linked_events, layout).is_err());
}

// Proves owner-only Watchdog paths reject a special bit preserved by native filesystems.
#[test]
fn native_storage_rejects_special_permission_bits() {
    let temporary = TempDir::new().unwrap();
    let layout = WatchdogStorageLayout::new(4, 2, 2).unwrap();

    let directory = temporary.path().join("sticky-directory");
    create_storage_directory(&directory);
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o1700)).unwrap();
    assert_eq!(
        fs::metadata(&directory).unwrap().permissions().mode() & 0o7777,
        0o1700
    );
    assert!(FilesystemWatchdogStorage::open_with_layout(&directory, layout).is_err());
}
