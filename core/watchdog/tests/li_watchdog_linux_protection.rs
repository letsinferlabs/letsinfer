// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use li_watchdog_manager::{
    LinuxWatchdogProtectionProvider, SystemWatchdogLinuxProcessProvider,
    SystemWatchdogLinuxProtectionFileProvider, WatchdogError, WatchdogLinuxCapability,
    WatchdogLinuxClock, WatchdogLinuxClocks, WatchdogLinuxFilesystemUsage,
    WatchdogLinuxHostFileProvider, WatchdogLinuxPidFd, WatchdogLinuxPidFdProvider,
    WatchdogLinuxProcessLayout, WatchdogLinuxProcessProvider, WatchdogLinuxProtectionFileProvider,
    WatchdogLinuxProtectionLayout, WatchdogLinuxSignal, WatchdogManager, WatchdogProcessState,
    WatchdogProtectedEngine, WatchdogProtectionPhase, WatchdogProtectionProvider,
    WatchdogSafetyAction, WatchdogSafetyEvent, WatchdogSafetyThresholds, WatchdogSample,
    WatchdogSampleProvider, WatchdogStorageProvider,
};

const SLOT: &str = "11111111111111111111111111111111";
const GENERATION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BOOT_ID: &str = "12345678-1234-1234-1234-123456789abc";
const CGROUP: &str = "/sys/fs/cgroup/user.slice/li_engine";

type Capability<T> = Result<WatchdogLinuxCapability<T>, WatchdogError>;

// Supplies queued read-only native values by exact path.
#[derive(Default)]
struct HostFileMock {
    reads: Mutex<BTreeMap<PathBuf, VecDeque<Capability<Vec<u8>>>>>,
}

impl HostFileMock {
    // Appends one available UTF-8 native file result.
    fn push_text(&self, path: impl Into<PathBuf>, value: impl AsRef<str>) {
        self.reads
            .lock()
            .unwrap()
            .entry(path.into())
            .or_default()
            .push_back(Ok(WatchdogLinuxCapability::Available(
                value.as_ref().as_bytes().to_vec(),
            )));
    }

    // Appends one explicit unsupported native file result.
    fn push_unsupported(&self, path: impl Into<PathBuf>) {
        self.reads
            .lock()
            .unwrap()
            .entry(path.into())
            .or_default()
            .push_back(Ok(WatchdogLinuxCapability::Unsupported));
    }
}

impl WatchdogLinuxHostFileProvider for HostFileMock {
    // Returns the next exact native read or explicit absence.
    fn read(
        &self,
        path: &Path,
        _maximum_bytes: usize,
    ) -> Result<WatchdogLinuxCapability<Vec<u8>>, WatchdogError> {
        self.reads
            .lock()
            .unwrap()
            .get_mut(path)
            .and_then(VecDeque::pop_front)
            .unwrap_or(Ok(WatchdogLinuxCapability::Unsupported))
    }

    // Keeps directory discovery unsupported for protection-focused fixtures.
    fn entries(
        &self,
        _path: &Path,
        _maximum_entries: usize,
    ) -> Result<WatchdogLinuxCapability<Vec<String>>, WatchdogError> {
        Ok(WatchdogLinuxCapability::Unsupported)
    }

    // Keeps filesystem capacity unsupported for protection-focused fixtures.
    fn filesystem_usage(
        &self,
        _path: &Path,
    ) -> Result<WatchdogLinuxCapability<WatchdogLinuxFilesystemUsage>, WatchdogError> {
        Ok(WatchdogLinuxCapability::Unsupported)
    }
}

// Records process signals and returns deterministic state and wait plans.
struct PidFdMock {
    states: Mutex<VecDeque<Result<WatchdogProcessState, WatchdogError>>>,
    waits: Mutex<VecDeque<Result<bool, WatchdogError>>>,
    signals: Mutex<Vec<WatchdogLinuxSignal>>,
    signal_failures: AtomicUsize,
}

impl PidFdMock {
    // Creates one running pidfd with caller-selected exit waits.
    fn new(waits: &[bool]) -> Self {
        Self {
            states: Mutex::new(VecDeque::new()),
            waits: Mutex::new(waits.iter().copied().map(Ok).collect()),
            signals: Mutex::new(Vec::new()),
            signal_failures: AtomicUsize::new(0),
        }
    }

    // Configures the next selected number of pidfd signal calls to fail.
    fn fail_signals(&self, failures: usize) {
        self.signal_failures.store(failures, Ordering::SeqCst);
    }
}

impl WatchdogLinuxPidFd for PidFdMock {
    // Returns the next state or a stable running default.
    fn state(&self) -> Result<WatchdogProcessState, WatchdogError> {
        self.states
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Ok(WatchdogProcessState::Running))
    }

    // Records one exact containment signal.
    fn signal(&self, signal: WatchdogLinuxSignal) -> Result<(), WatchdogError> {
        self.signals.lock().unwrap().push(signal);
        if self.signal_failures.load(Ordering::SeqCst) > 0 {
            self.signal_failures.fetch_sub(1, Ordering::SeqCst);
            return Err(WatchdogError::provider("pidfd mock", "signal failed"));
        }
        Ok(())
    }

    // Returns the next exact bounded-wait result.
    fn wait_for_exit(&self, _duration: Duration) -> Result<bool, WatchdogError> {
        self.waits.lock().unwrap().pop_front().unwrap_or(Ok(true))
    }
}

// Supplies ordered pidfd open states and records exact process identities.
struct PidFdProviderMock {
    plans: Mutex<VecDeque<Capability<Option<Arc<dyn WatchdogLinuxPidFd>>>>>,
    calls: Mutex<Vec<u32>>,
}

impl PidFdProviderMock {
    // Creates one provider from exact capability plans.
    fn new(plans: Vec<Capability<Option<Arc<dyn WatchdogLinuxPidFd>>>>) -> Self {
        Self {
            plans: Mutex::new(plans.into()),
            calls: Mutex::new(Vec::new()),
        }
    }
}

impl WatchdogLinuxPidFdProvider for PidFdProviderMock {
    // Returns the next exact pidfd capability result.
    fn open(
        &self,
        process_id: u32,
    ) -> Result<WatchdogLinuxCapability<Option<Arc<dyn WatchdogLinuxPidFd>>>, WatchdogError> {
        self.calls.lock().unwrap().push(process_id);
        self.plans
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| Err(WatchdogError::provider("pidfd mock", "exhausted")))
    }
}

// Supplies descriptor slots and private-file outcomes while recording durable writes.
#[derive(Default)]
struct ProtectionFileMock {
    slot_plans: Mutex<VecDeque<Result<Vec<String>, WatchdogError>>>,
    reads: Mutex<BTreeMap<PathBuf, VecDeque<Result<Option<Vec<u8>>, WatchdogError>>>>,
    writes: Mutex<Vec<(PathBuf, Vec<u8>)>>,
    write_failures: AtomicUsize,
}

impl ProtectionFileMock {
    // Appends one exact protection slot set.
    fn push_slots(&self, slots: &[&str]) {
        self.slot_plans
            .lock()
            .unwrap()
            .push_back(Ok(slots.iter().map(|value| value.to_string()).collect()));
    }

    // Appends one private UTF-8 file result.
    fn push_text(&self, path: impl Into<PathBuf>, value: &str) {
        self.reads
            .lock()
            .unwrap()
            .entry(path.into())
            .or_default()
            .push_back(Ok(Some(value.as_bytes().to_vec())));
    }

    // Appends one absent private file result.
    fn push_absent(&self, path: impl Into<PathBuf>) {
        self.reads
            .lock()
            .unwrap()
            .entry(path.into())
            .or_default()
            .push_back(Ok(None));
    }
}

impl WatchdogLinuxProtectionFileProvider for ProtectionFileMock {
    // Returns the next exact slot set without inspecting the test host.
    fn slots(&self, _root: &Path, _maximum_slots: usize) -> Result<Vec<String>, WatchdogError> {
        self.slot_plans
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| Ok(Vec::new()))
    }

    // Returns one queued private-file state or exact absence.
    fn read_private_file(
        &self,
        path: &Path,
        _maximum_bytes: usize,
    ) -> Result<Option<Vec<u8>>, WatchdogError> {
        self.reads
            .lock()
            .unwrap()
            .get_mut(path)
            .and_then(VecDeque::pop_front)
            .unwrap_or(Ok(None))
    }

    // Records one durable write or fails its configured boundary.
    fn write_atomic_private_file(&self, path: &Path, payload: &[u8]) -> Result<(), WatchdogError> {
        self.writes
            .lock()
            .unwrap()
            .push((path.to_path_buf(), payload.to_vec()));
        if self.write_failures.load(Ordering::SeqCst) > 0 {
            self.write_failures.fetch_sub(1, Ordering::SeqCst);
            return Err(WatchdogError::provider("protection file mock", "failed"));
        }
        Ok(())
    }
}

// Supplies process bindings, cgroup state, and deterministic polling observations.
struct ProcessProviderMock {
    process: Arc<PidFdMock>,
    process_is_bound: bool,
    binds: AtomicUsize,
    empty: Mutex<VecDeque<Result<bool, WatchdogError>>>,
    cgroup_checks: AtomicUsize,
    kills: AtomicUsize,
    waits: AtomicUsize,
}

impl ProcessProviderMock {
    // Creates one available bound process and exact cgroup-empty plan.
    fn new(process: Arc<PidFdMock>, empty: &[bool]) -> Self {
        Self {
            process,
            process_is_bound: true,
            binds: AtomicUsize::new(0),
            empty: Mutex::new(empty.iter().copied().map(Ok).collect()),
            cgroup_checks: AtomicUsize::new(0),
            kills: AtomicUsize::new(0),
            waits: AtomicUsize::new(0),
        }
    }

    // Creates one provider whose descriptor process has already exited.
    fn exited(process: Arc<PidFdMock>) -> Self {
        Self {
            process,
            process_is_bound: false,
            binds: AtomicUsize::new(0),
            empty: Mutex::new(VecDeque::new()),
            cgroup_checks: AtomicUsize::new(0),
            kills: AtomicUsize::new(0),
            waits: AtomicUsize::new(0),
        }
    }
}

impl WatchdogLinuxProcessProvider for ProcessProviderMock {
    // Returns the exact mock pidfd and records each descriptor bind.
    fn bind(
        &self,
        _target: &WatchdogProtectedEngine,
    ) -> Result<Option<Arc<dyn WatchdogLinuxPidFd>>, WatchdogError> {
        self.binds.fetch_add(1, Ordering::SeqCst);
        Ok(self
            .process_is_bound
            .then(|| self.process.clone() as Arc<dyn WatchdogLinuxPidFd>))
    }

    // Returns the next cgroup-empty observation.
    fn cgroup_is_empty(&self, _cgroup: &str) -> Result<bool, WatchdogError> {
        self.cgroup_checks.fetch_add(1, Ordering::SeqCst);
        self.empty.lock().unwrap().pop_front().unwrap_or(Ok(true))
    }

    // Records one last-resort exact-cgroup kill pass.
    fn kill_cgroup_members(&self, _cgroup: &str) -> Result<(), WatchdogError> {
        self.kills.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    // Records one bounded cgroup polling interval without sleeping.
    fn wait(&self, _duration: Duration) {
        self.waits.fetch_add(1, Ordering::SeqCst);
    }
}

// Supplies one stable deterministic trip timestamp.
struct ClockMock;

impl WatchdogLinuxClock for ClockMock {
    // Returns exact positive wall and monotonic values.
    fn clocks(&self) -> Result<WatchdogLinuxClocks, WatchdogError> {
        WatchdogLinuxClocks::new(1_700_000_000_123, 10_000)
    }
}

// Supplies deterministic manager samples while real Linux protection owns safety observation.
struct ManagerSampleMock;

impl WatchdogSampleProvider for ManagerSampleMock {
    // Returns one exact sample for the manager's requested durable sequence.
    fn sample(&self, sequence: u64) -> Result<WatchdogSample, WatchdogError> {
        WatchdogSample::new(sequence, 1_700_000_000_000 + sequence, 10_000 + sequence)
    }
}

// Records manager event attempts and injects only the selected publication failure.
#[derive(Default)]
struct ManagerStorageMock {
    event_failures: AtomicUsize,
    event_calls: AtomicUsize,
}

impl WatchdogStorageProvider for ManagerStorageMock {
    // Starts each recreated manager from the same incomplete durable tick.
    fn next_sequence(&self) -> Result<u64, WatchdogError> {
        Ok(1)
    }

    // Accepts idempotent sample replay while the protection latch remains authoritative.
    fn record_sample(&self, _sample: &WatchdogSample) -> Result<(), WatchdogError> {
        Ok(())
    }

    // Records one exact event attempt and fails only its configured publication boundary.
    fn record_event(&self, _event: &WatchdogSafetyEvent) -> Result<(), WatchdogError> {
        self.event_calls.fetch_add(1, Ordering::SeqCst);
        if self.event_failures.load(Ordering::SeqCst) > 0 {
            self.event_failures.fetch_sub(1, Ordering::SeqCst);
            return Err(WatchdogError::provider("event mock", "publication failed"));
        }
        Ok(())
    }

    // Accepts explicit manager flush boundaries without masking the event failure under test.
    fn flush(&self) -> Result<(), WatchdogError> {
        Ok(())
    }
}

// Returns the exact manager safety thresholds used for Linux protection restart coverage.
fn manager_thresholds() -> WatchdogSafetyThresholds {
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

// Returns one exact armed version-one descriptor.
fn armed_descriptor() -> String {
    format!(
        "version=1\ngeneration={GENERATION}\nphase=armed\ncontainer_name=li_engine\ncontainer_id={}\npid=1234\nstart_ticks=5678\nboot_id={BOOT_ID}\ncgroup={CGROUP}\n",
        "b".repeat(64)
    )
}

// Returns one exact disarmed version-one descriptor.
fn disarmed_descriptor() -> String {
    format!(
        "version=1\ngeneration={GENERATION}\nphase=disarmed\ncontainer_name=li_engine\ncontainer_id=-\npid=-\nstart_ticks=-\nboot_id=-\ncgroup=-\n"
    )
}

// Returns one proc stat record whose field 22 is the selected start tick.
fn process_stat(process_id: u32, start_ticks: u64) -> String {
    let mut fields = vec!["0".to_string(); 20];
    fields[0] = "R".to_string();
    fields[19] = start_ticks.to_string();
    format!("{process_id} (li engine worker) {}\n", fields.join(" "))
}

// Queues one complete process identity before and after pidfd acquisition.
fn queue_process_identity(files: &HostFileMock, process_id: u32, start_ticks: u64, cgroup: &str) {
    for _ in 0..2 {
        queue_process_identity_once(files, process_id, start_ticks, cgroup);
    }
}

// Queues one complete process identity read.
fn queue_process_identity_once(
    files: &HostFileMock,
    process_id: u32,
    start_ticks: u64,
    cgroup: &str,
) {
    files.push_text(
        format!("/proc/{process_id}/stat"),
        process_stat(process_id, start_ticks),
    );
    files.push_text(
        format!("/proc/{process_id}/cgroup"),
        format!("0::{}\n", &cgroup[14..]),
    );
    files.push_text("/proc/sys/kernel/random/boot_id", format!("{BOOT_ID}\n"));
}

// Returns one deterministic sample consumed only as an observation transaction identity.
fn sample(sequence: u64) -> WatchdogSample {
    WatchdogSample::new(sequence, 1_700_000_000_000 + sequence, 10_000 + sequence).unwrap()
}

// Returns one test protection layout rooted away from the production state directory.
fn protection_layout() -> WatchdogLinuxProtectionLayout {
    WatchdogLinuxProtectionLayout::new(
        PathBuf::from("/test/protected-placements"),
        PathBuf::from("/proc/meminfo"),
        PathBuf::from("/proc/pressure/memory"),
    )
    .unwrap()
}

// Returns the exact private file path for one test slot peer.
fn slot_file(name: &str) -> PathBuf {
    PathBuf::from("/test/protected-placements")
        .join(SLOT)
        .join(name)
}

// Queues one complete protection safety observation.
fn queue_safety(
    host: &HostFileMock,
    pressure_some: u64,
    pressure_full: u64,
    oom: u64,
    oom_kill: u64,
    oom_group_kill: u64,
    maximum: u64,
) {
    host.push_text(
        "/proc/meminfo",
        "MemAvailable: 8388608 kB\nSwapTotal: 2097152 kB\nSwapFree: 1048576 kB\n",
    );
    host.push_text(
        "/proc/pressure/memory",
        format!(
            "some avg10=0.00 avg60=0.00 avg300=0.00 total={pressure_some}\nfull avg10=0.00 avg60=0.00 avg300=0.00 total={pressure_full}\n"
        ),
    );
    host.push_text(
        format!("{CGROUP}/memory.events"),
        format!(
            "low 0\nhigh 0\nmax {maximum}\noom {oom}\noom_kill {oom_kill}\noom_group_kill {oom_group_kill}\n"
        ),
    );
}

// Proves the production process provider double-checks start, boot, and cgroup around pidfd open.
#[test]
fn linux_process_provider_binds_only_an_exact_descriptor_identity() {
    let target = WatchdogProtectedEngine::parse(&armed_descriptor()).unwrap();
    let files = Arc::new(HostFileMock::default());
    queue_process_identity(&files, 1234, 5678, CGROUP);
    let pidfd = Arc::new(PidFdMock::new(&[]));
    let pidfds = Arc::new(PidFdProviderMock::new(vec![Ok(
        WatchdogLinuxCapability::Available(Some(pidfd.clone())),
    )]));
    let provider = SystemWatchdogLinuxProcessProvider::new(
        WatchdogLinuxProcessLayout::system(),
        files,
        pidfds.clone(),
    );

    let bound = provider.bind(&target).unwrap().unwrap();

    assert_eq!(bound.state().unwrap(), WatchdogProcessState::Running);
    assert_eq!(pidfds.calls.lock().unwrap().as_slice(), [1234]);

    let files = Arc::new(HostFileMock::default());
    queue_process_identity(&files, 1234, 9999, CGROUP);
    let provider = SystemWatchdogLinuxProcessProvider::new(
        WatchdogLinuxProcessLayout::system(),
        files,
        Arc::new(PidFdProviderMock::new(Vec::new())),
    );
    assert!(provider.bind(&target).is_err());

    let files = Arc::new(HostFileMock::default());
    queue_process_identity_once(&files, 1234, 5678, CGROUP);
    queue_process_identity_once(&files, 1234, 5679, CGROUP);
    let provider = SystemWatchdogLinuxProcessProvider::new(
        WatchdogLinuxProcessLayout::system(),
        files,
        Arc::new(PidFdProviderMock::new(vec![Ok(
            WatchdogLinuxCapability::Available(Some(Arc::new(PidFdMock::new(&[])))),
        )])),
    );
    assert!(provider.bind(&target).is_err());

    let files = Arc::new(HostFileMock::default());
    queue_process_identity(&files, 1234, 5678, CGROUP);
    let provider = SystemWatchdogLinuxProcessProvider::new(
        WatchdogLinuxProcessLayout::system(),
        files,
        Arc::new(PidFdProviderMock::new(vec![Ok(
            WatchdogLinuxCapability::Unsupported,
        )])),
    );
    assert!(provider.bind(&target).is_err());

    let provider = SystemWatchdogLinuxProcessProvider::new(
        WatchdogLinuxProcessLayout::system(),
        Arc::new(HostFileMock::default()),
        Arc::new(PidFdProviderMock::new(Vec::new())),
    );
    assert!(provider.bind(&target).unwrap().is_none());
}

// Proves last-resort cgroup containment signals only currently revalidated member pidfds.
#[test]
fn linux_process_provider_bounds_and_revalidates_cgroup_members() {
    let files = Arc::new(HostFileMock::default());
    files.push_text(format!("{CGROUP}/cgroup.procs"), "100\n101\n102\n");
    files.push_text("/proc/100/cgroup", format!("0::{}\n", &CGROUP[14..]));
    files.push_text("/proc/101/cgroup", "0::/foreign.slice\n");
    files.push_unsupported("/proc/102/cgroup");
    files.push_text(format!("{CGROUP}/cgroup.procs"), "\n");
    let member = Arc::new(PidFdMock::new(&[]));
    let pidfds = Arc::new(PidFdProviderMock::new(vec![Ok(
        WatchdogLinuxCapability::Available(Some(member.clone())),
    )]));
    let provider = SystemWatchdogLinuxProcessProvider::new(
        WatchdogLinuxProcessLayout::system(),
        files,
        pidfds.clone(),
    );

    provider.kill_cgroup_members(CGROUP).unwrap();

    assert_eq!(
        member.signals.lock().unwrap().as_slice(),
        [WatchdogLinuxSignal::Kill]
    );
    assert_eq!(pidfds.calls.lock().unwrap().as_slice(), [100]);
    assert!(provider.cgroup_is_empty(CGROUP).unwrap());
    assert!(provider.cgroup_is_empty("/tmp/foreign").is_err());
}

// Proves sampling baselines, exact acknowledgement, trip bytes, and bounded escalation compose.
#[test]
fn linux_protection_provider_completes_observation_trip_and_containment() {
    let files = Arc::new(ProtectionFileMock::default());
    for _ in 0..2 {
        files.push_slots(&[SLOT]);
        files.push_text(slot_file("protected-placement.state"), &armed_descriptor());
        files.push_absent(slot_file("protection-trip.json"));
    }
    let host = Arc::new(HostFileMock::default());
    queue_safety(&host, 100, 20, 10, 2, 0, 5);
    queue_safety(&host, 150, 30, 12, 3, 1, 9);
    let pidfd = Arc::new(PidFdMock::new(&[false, true]));
    let processes = Arc::new(ProcessProviderMock::new(
        pidfd.clone(),
        &[false, false, true],
    ));
    let provider = LinuxWatchdogProtectionProvider::new(
        protection_layout(),
        files.clone(),
        host,
        processes.clone(),
        Arc::new(ClockMock),
    );

    let first = provider.observations(&sample(1)).unwrap();
    let second = provider.observations(&sample(2)).unwrap();

    assert_eq!(first.len(), 1);
    assert_eq!(first[0].safety().psi_some_delta_microseconds, 0);
    assert_eq!(second[0].safety().available_bytes, 8 << 30);
    assert_eq!(second[0].safety().swap_used_bytes, 1 << 30);
    assert_eq!(second[0].safety().psi_some_delta_microseconds, 50);
    assert_eq!(second[0].safety().psi_full_delta_microseconds, 10);
    assert_eq!(second[0].safety().cgroup_oom_delta, 2);
    assert_eq!(second[0].safety().cgroup_oom_kill_delta, 1);
    assert_eq!(second[0].safety().cgroup_oom_group_kill_delta, 1);
    assert_eq!(second[0].safety().cgroup_max_delta, 4);
    assert_eq!(processes.binds.load(Ordering::SeqCst), 1);

    provider
        .latch_trip(
            second[0].target(),
            WatchdogSafetyAction::Kill,
            "cgroup_oom_kill",
            second[0].safety(),
        )
        .unwrap();
    assert!(provider
        .contain(second[0].target(), WatchdogSafetyAction::Stop, 5_000)
        .unwrap());

    let writes = files.writes.lock().unwrap();
    assert_eq!(writes.len(), 2);
    assert_eq!(
        String::from_utf8(writes[0].1.clone()).unwrap(),
        format!(
            "version=1\ngeneration={GENERATION}\nphase=armed\ncontainer_id={}\n",
            "b".repeat(64)
        )
    );
    assert_eq!(
        String::from_utf8(writes[1].1.clone()).unwrap(),
        format!(
            "{{\n  \"schema_version\": 1,\n  \"timestamp_unix_ms\": 1700000000123,\n  \"generation\": \"{GENERATION}\",\n  \"container_id\": \"{}\",\n  \"action\": \"kill\",\n  \"reason\": \"cgroup_oom_kill\",\n  \"available_bytes\": {},\n  \"swap_used_bytes\": {}\n}}\n",
            "b".repeat(64),
            8_u64 << 30,
            1_u64 << 30
        )
    );
    assert_eq!(
        pidfd.signals.lock().unwrap().as_slice(),
        [WatchdogLinuxSignal::Terminate, WatchdogLinuxSignal::Kill]
    );
    assert_eq!(processes.kills.load(Ordering::SeqCst), 1);
    assert_eq!(processes.waits.load(Ordering::SeqCst), 1);
}

// Proves a recreated manager reads the durable Linux trip file and never repeats containment.
#[test]
fn linux_trip_file_remains_authoritative_after_event_publication_failure_and_restart() {
    let files = Arc::new(ProtectionFileMock::default());
    files.push_slots(&[SLOT]);
    files.push_text(slot_file("protected-placement.state"), &armed_descriptor());
    files.push_absent(slot_file("protection-trip.json"));
    let first_host = Arc::new(HostFileMock::default());
    queue_safety(&first_host, 1, 1, 1, 0, 0, 1);
    let first_processes = Arc::new(ProcessProviderMock::exited(Arc::new(PidFdMock::new(&[]))));
    let first_protection = Arc::new(LinuxWatchdogProtectionProvider::new(
        protection_layout(),
        files.clone(),
        first_host,
        first_processes.clone(),
        Arc::new(ClockMock),
    ));
    let storage = Arc::new(ManagerStorageMock::default());
    storage.event_failures.store(1, Ordering::SeqCst);
    let first_manager = WatchdogManager::new(
        manager_thresholds(),
        Arc::new(ManagerSampleMock),
        first_protection,
        storage.clone(),
    )
    .unwrap();

    assert!(first_manager.tick().is_err());
    assert_eq!(first_processes.cgroup_checks.load(Ordering::SeqCst), 1);
    let trip_payload = files
        .writes
        .lock()
        .unwrap()
        .iter()
        .find(|(path, _)| path == &slot_file("protection-trip.json"))
        .map(|(_, payload)| String::from_utf8(payload.clone()).unwrap())
        .expect("durable Linux trip payload");

    files.push_slots(&[SLOT]);
    files.push_text(slot_file("protected-placement.state"), &armed_descriptor());
    files.push_text(slot_file("protection-trip.json"), &trip_payload);
    let restarted_host = Arc::new(HostFileMock::default());
    queue_safety(&restarted_host, 1, 1, 1, 0, 0, 1);
    let restarted_processes = Arc::new(ProcessProviderMock::exited(Arc::new(PidFdMock::new(&[]))));
    let restarted_protection = Arc::new(LinuxWatchdogProtectionProvider::new(
        protection_layout(),
        files.clone(),
        restarted_host,
        restarted_processes.clone(),
        Arc::new(ClockMock),
    ));
    let restarted_manager = WatchdogManager::new(
        manager_thresholds(),
        Arc::new(ManagerSampleMock),
        restarted_protection,
        storage.clone(),
    )
    .unwrap();

    let recovered = restarted_manager.tick().unwrap();

    assert!(recovered.events().is_empty());
    assert_eq!(storage.event_calls.load(Ordering::SeqCst), 1);
    assert_eq!(restarted_processes.cgroup_checks.load(Ordering::SeqCst), 0);
    assert_eq!(
        files
            .writes
            .lock()
            .unwrap()
            .iter()
            .filter(|(path, _)| path == &slot_file("protection-trip.json"))
            .count(),
        1
    );
}

// Proves a pidfd signaling failure still attempts exact-cgroup containment before reporting success.
#[test]
fn linux_protection_provider_continues_to_cgroup_after_pidfd_failure() {
    let files = Arc::new(ProtectionFileMock::default());
    files.push_slots(&[SLOT]);
    files.push_text(slot_file("protected-placement.state"), &armed_descriptor());
    files.push_absent(slot_file("protection-trip.json"));
    let host = Arc::new(HostFileMock::default());
    queue_safety(&host, 1, 1, 1, 0, 0, 1);
    let pidfd = Arc::new(PidFdMock::new(&[]));
    pidfd.fail_signals(1);
    let processes = Arc::new(ProcessProviderMock::new(pidfd, &[false, true]));
    let provider = LinuxWatchdogProtectionProvider::new(
        protection_layout(),
        files,
        host,
        processes.clone(),
        Arc::new(ClockMock),
    );
    let observations = provider.observations(&sample(1)).unwrap();

    assert!(provider
        .contain(observations[0].target(), WatchdogSafetyAction::Kill, 1_000,)
        .unwrap());
    assert_eq!(processes.kills.load(Ordering::SeqCst), 1);
}

// Proves unsupported PSI is non-destructive while active slots survive transient root omission.
#[test]
fn linux_protection_provider_retains_active_slots_and_bounds_discovery() {
    let files = Arc::new(ProtectionFileMock::default());
    files.push_slots(&[SLOT]);
    files.push_slots(&[]);
    files.push_text(slot_file("protected-placement.state"), &armed_descriptor());
    files.push_absent(slot_file("protection-trip.json"));
    files.push_absent(slot_file("protection-trip.json"));
    let host = Arc::new(HostFileMock::default());
    for events in ["max 1\noom 1\noom_kill 0\n", "max 2\noom 2\noom_kill 0\n"] {
        host.push_text(
            "/proc/meminfo",
            "MemAvailable: 1024 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n",
        );
        host.push_unsupported("/proc/pressure/memory");
        host.push_text(format!("{CGROUP}/memory.events"), events);
    }
    let pidfd = Arc::new(PidFdMock::new(&[]));
    let processes = Arc::new(ProcessProviderMock::new(pidfd, &[]));
    let provider = LinuxWatchdogProtectionProvider::new(
        protection_layout(),
        files,
        host,
        processes.clone(),
        Arc::new(ClockMock),
    );

    assert_eq!(provider.observations(&sample(1)).unwrap().len(), 1);
    let retained = provider.observations(&sample(2)).unwrap();

    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0].safety().psi_some_delta_microseconds, 0);
    assert_eq!(retained[0].safety().cgroup_oom_delta, 1);
    assert_eq!(processes.binds.load(Ordering::SeqCst), 1);

    let files = Arc::new(ProtectionFileMock::default());
    let slots = (0..=64)
        .map(|index| format!("{index:032x}"))
        .collect::<Vec<_>>();
    files.slot_plans.lock().unwrap().push_back(Ok(slots));
    let provider = LinuxWatchdogProtectionProvider::new(
        protection_layout(),
        files,
        Arc::new(HostFileMock::default()),
        Arc::new(ProcessProviderMock::new(Arc::new(PidFdMock::new(&[])), &[])),
        Arc::new(ClockMock),
    );
    assert!(provider.observations(&sample(1)).is_err());

    let other_slot = "22222222222222222222222222222222";
    let files = Arc::new(ProtectionFileMock::default());
    files.push_slots(&[SLOT, other_slot]);
    files.push_text(slot_file("protected-placement.state"), &armed_descriptor());
    files.push_text(
        PathBuf::from("/test/protected-placements")
            .join(other_slot)
            .join("protected-placement.state"),
        &armed_descriptor(),
    );
    let provider = LinuxWatchdogProtectionProvider::new(
        protection_layout(),
        files.clone(),
        Arc::new(HostFileMock::default()),
        Arc::new(ProcessProviderMock::new(Arc::new(PidFdMock::new(&[])), &[])),
        Arc::new(ClockMock),
    );
    assert!(provider.observations(&sample(1)).is_err());
    assert!(files.writes.lock().unwrap().is_empty());
}

// Proves an already-exited process is observed for a durable trip without falsely acknowledging binding.
#[test]
fn linux_protection_provider_does_not_acknowledge_an_unbound_active_process() {
    let files = Arc::new(ProtectionFileMock::default());
    files.push_slots(&[SLOT]);
    files.push_text(slot_file("protected-placement.state"), &armed_descriptor());
    files.push_absent(slot_file("protection-trip.json"));
    let host = Arc::new(HostFileMock::default());
    queue_safety(&host, 1, 1, 1, 0, 0, 1);
    let processes = Arc::new(ProcessProviderMock::exited(Arc::new(PidFdMock::new(&[]))));
    let provider = LinuxWatchdogProtectionProvider::new(
        protection_layout(),
        files.clone(),
        host,
        processes,
        Arc::new(ClockMock),
    );

    let observations = provider.observations(&sample(1)).unwrap();

    assert_eq!(
        observations[0].process_state(),
        WatchdogProcessState::Exited
    );
    assert!(files.writes.lock().unwrap().is_empty());
}

// Proves malformed memory, PSI, and cgroup sources fail before acknowledgement or baseline commit.
#[test]
fn linux_protection_provider_rejects_each_malformed_safety_boundary() {
    let cases = [
        (
            "SwapTotal: 0 kB\nSwapFree: 0 kB\n",
            "some total=1\nfull total=1\n",
            "max 1\noom 1\noom_kill 0\n",
        ),
        (
            "MemAvailable: 1024 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n",
            "some total=1\n",
            "max 1\noom 1\noom_kill 0\n",
        ),
        (
            "MemAvailable: 1024 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n",
            "some total=1\nfull total=1\n",
            "max 1\noom 1\n",
        ),
    ];
    for (memory, pressure, events) in cases {
        let files = Arc::new(ProtectionFileMock::default());
        files.push_slots(&[SLOT]);
        files.push_text(slot_file("protected-placement.state"), &armed_descriptor());
        files.push_absent(slot_file("protection-trip.json"));
        let host = Arc::new(HostFileMock::default());
        host.push_text("/proc/meminfo", memory);
        host.push_text("/proc/pressure/memory", pressure);
        host.push_text(format!("{CGROUP}/memory.events"), events);
        let provider = LinuxWatchdogProtectionProvider::new(
            protection_layout(),
            files.clone(),
            host,
            Arc::new(ProcessProviderMock::new(Arc::new(PidFdMock::new(&[])), &[])),
            Arc::new(ClockMock),
        );

        assert!(provider.observations(&sample(1)).is_err());
        assert!(files.writes.lock().unwrap().is_empty());
    }
}

// Proves failed acknowledgement does not commit a binding and disarm acknowledgement is idempotent.
#[test]
fn linux_protection_provider_retries_failed_commit_and_acknowledges_disarm() {
    let files = Arc::new(ProtectionFileMock::default());
    for _ in 0..2 {
        files.push_slots(&[SLOT]);
        files.push_text(slot_file("protected-placement.state"), &armed_descriptor());
        files.push_absent(slot_file("protection-trip.json"));
    }
    files.write_failures.store(1, Ordering::SeqCst);
    let host = Arc::new(HostFileMock::default());
    queue_safety(&host, 1, 1, 1, 0, 0, 1);
    queue_safety(&host, 1, 1, 1, 0, 0, 1);
    let processes = Arc::new(ProcessProviderMock::new(Arc::new(PidFdMock::new(&[])), &[]));
    let provider = LinuxWatchdogProtectionProvider::new(
        protection_layout(),
        files,
        host,
        processes.clone(),
        Arc::new(ClockMock),
    );

    assert!(provider.observations(&sample(1)).is_err());
    assert!(provider.observations(&sample(1)).is_ok());
    assert_eq!(processes.binds.load(Ordering::SeqCst), 2);

    let files = Arc::new(ProtectionFileMock::default());
    files.push_slots(&[SLOT]);
    files.push_text(
        slot_file("protected-placement.state"),
        &disarmed_descriptor(),
    );
    files.push_absent(slot_file("protection-trip.json"));
    let provider = LinuxWatchdogProtectionProvider::new(
        protection_layout(),
        files.clone(),
        Arc::new(HostFileMock::default()),
        Arc::new(ProcessProviderMock::new(Arc::new(PidFdMock::new(&[])), &[])),
        Arc::new(ClockMock),
    );
    let observations = provider.observations(&sample(1)).unwrap();
    assert_eq!(
        observations[0].target().phase(),
        WatchdogProtectionPhase::Disarmed
    );
    provider
        .acknowledge_disarmed(observations[0].target())
        .unwrap();
    assert_eq!(files.writes.lock().unwrap().len(), 2);
}

// Proves the system protection filesystem accepts only owner-only directories and regular files.
#[test]
fn system_linux_protection_files_are_private_bounded_and_no_follow() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("protected-placements");
    let slot = root.join(SLOT);
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir(&slot).unwrap();
    fs::set_permissions(&slot, fs::Permissions::from_mode(0o700)).unwrap();
    let provider = SystemWatchdogLinuxProtectionFileProvider::current_user();

    assert_eq!(provider.slots(&root, 64).unwrap(), [SLOT]);
    let state = slot.join("protected-placement.state");
    provider
        .write_atomic_private_file(&state, armed_descriptor().as_bytes())
        .unwrap();
    assert_eq!(
        provider.read_private_file(&state, 2_048).unwrap().unwrap(),
        armed_descriptor().as_bytes()
    );

    let linked = slot.join("linked.state");
    symlink(&state, &linked).unwrap();
    assert!(provider.read_private_file(&linked, 2_048).is_err());
    fs::set_permissions(&state, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(provider.read_private_file(&state, 2_048).is_err());
    fs::set_permissions(&root, fs::Permissions::from_mode(0o750)).unwrap();
    assert!(provider.slots(&root, 64).is_err());
}
