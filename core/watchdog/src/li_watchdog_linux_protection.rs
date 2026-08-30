// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::{
    maximum_watchdog_targets, SystemWatchdogLinuxClock, SystemWatchdogLinuxHostFileProvider,
    SystemWatchdogLinuxPidFdProvider, SystemWatchdogLinuxProcessProvider, WatchdogError,
    WatchdogLinuxCapability, WatchdogLinuxClock, WatchdogLinuxHostFileProvider, WatchdogLinuxPidFd,
    WatchdogLinuxProcessLayout, WatchdogLinuxProcessProvider, WatchdogLinuxSignal,
    WatchdogProcessState, WatchdogProtectedEngine, WatchdogProtectionObservation,
    WatchdogProtectionPhase, WatchdogProtectionProvider, WatchdogSafetyAction, WatchdogSafetyInput,
    WatchdogSample,
};

const PROTECTION_ROOT_NAME: &str = "protected-placements";
const PROTECTION_STATE_NAME: &str = "protected-placement.state";
const PROTECTION_ACKNOWLEDGEMENT_NAME: &str = "protected-placement.ack";
const PROTECTION_TRIP_NAME: &str = "protection-trip.json";
const MAX_DESCRIPTOR_BYTES: usize = 2_048;
const MAX_ACKNOWLEDGEMENT_BYTES: usize = 512;
const MAX_TRIP_BYTES: usize = 16_384;
const MAX_MEMINFO_BYTES: usize = 16 * 1_024;
const MAX_PRESSURE_BYTES: usize = 1_024;
const MAX_CGROUP_EVENTS_BYTES: usize = 2_048;
const MAX_DIRECTORY_ENTRIES: usize = 1_024;
const MAX_NATIVE_PATH_BYTES: usize = 4_095;
const CONTAINMENT_ESCALATION_MILLISECONDS: u64 = 1_000;
const CGROUP_EMPTY_ATTEMPTS: usize = 20;
const CGROUP_EMPTY_INTERVAL_MILLISECONDS: u64 = 100;

// Isolates owner-bound protection slot discovery and durable private-file mutation.
pub trait WatchdogLinuxProtectionFileProvider: Send + Sync {
    // Lists every valid owner-bound protection slot under a hard total-entry bound.
    fn slots(&self, root: &Path, maximum_slots: usize) -> Result<Vec<String>, WatchdogError>;

    // Reads one bounded owner-only regular file without following its final component.
    fn read_private_file(
        &self,
        path: &Path,
        maximum_bytes: usize,
    ) -> Result<Option<Vec<u8>>, WatchdogError>;

    // Atomically replaces one owner-only regular file and synchronizes its directory.
    fn write_atomic_private_file(&self, path: &Path, payload: &[u8]) -> Result<(), WatchdogError>;
}

// Describes exact durable and kernel paths consumed by Linux protection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogLinuxProtectionLayout {
    protected_placements_root: PathBuf,
    meminfo: PathBuf,
    memory_pressure: PathBuf,
}

impl WatchdogLinuxProtectionLayout {
    // Creates one explicit Linux protection layout after closing traversal ambiguity.
    pub fn new(
        protected_placements_root: PathBuf,
        meminfo: PathBuf,
        memory_pressure: PathBuf,
    ) -> Result<Self, WatchdogError> {
        for path in [&protected_placements_root, &meminfo, &memory_pressure] {
            validate_protection_path(path)?;
        }
        if protected_placements_root
            .file_name()
            .and_then(|name| name.to_str())
            != Some(PROTECTION_ROOT_NAME)
        {
            return Err(WatchdogError::InvalidContract {
                reason: "Linux protection root identity is invalid",
            });
        }
        Ok(Self {
            protected_placements_root,
            meminfo,
            memory_pressure,
        })
    }

    // Returns the fixed production Linux protection and procfs layout.
    pub fn system() -> Self {
        Self::new(
            PathBuf::from("/var/lib/letsinfer/watchdog/protected-placements"),
            PathBuf::from("/proc/meminfo"),
            PathBuf::from("/proc/pressure/memory"),
        )
        .expect("fixed Linux Watchdog protection layout")
    }

    // Returns one exact protection slot path from a closed slot identity.
    fn slot_root(&self, slot: &str) -> PathBuf {
        self.protected_placements_root.join(slot)
    }

    // Returns one exact file inside a closed protection slot identity.
    fn slot_file(&self, slot: &str, name: &'static str) -> PathBuf {
        self.slot_root(slot).join(name)
    }
}

// Performs owner-checked no-follow protection file operations.
pub struct SystemWatchdogLinuxProtectionFileProvider {
    owner_user_id: u32,
    temporary_counter: AtomicU64,
}

impl SystemWatchdogLinuxProtectionFileProvider {
    // Creates one provider for the explicitly selected service owner.
    pub const fn new(owner_user_id: u32) -> Self {
        Self {
            owner_user_id,
            temporary_counter: AtomicU64::new(0),
        }
    }

    // Creates one provider for the current effective service owner.
    pub fn current_user() -> Self {
        // SAFETY: geteuid has no preconditions and retains no memory.
        let owner_user_id = unsafe { libc::geteuid() };
        Self::new(owner_user_id)
    }
}

impl WatchdogLinuxProtectionFileProvider for SystemWatchdogLinuxProtectionFileProvider {
    // Lists private target directories while ignoring unrelated names like the C supervisor.
    fn slots(&self, root: &Path, maximum_slots: usize) -> Result<Vec<String>, WatchdogError> {
        if maximum_slots == 0 || maximum_slots > maximum_watchdog_targets() {
            return Err(protection_file_error("protection slot bound is invalid"));
        }
        validate_private_directory_path(root, self.owner_user_id)?;
        let directory = fs::read_dir(root)
            .map_err(|_| protection_file_error("protection root could not be listed"))?;
        let mut total_entries = 0_usize;
        let mut slots = Vec::new();
        for entry in directory {
            let entry = entry
                .map_err(|_| protection_file_error("protection root changed during listing"))?;
            total_entries = total_entries.saturating_add(1);
            if total_entries > MAX_DIRECTORY_ENTRIES {
                return Err(protection_file_error(
                    "protection root exceeded its entry bound",
                ));
            }
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            if !valid_slot_name(&name) {
                continue;
            }
            validate_private_directory_path(&entry.path(), self.owner_user_id)?;
            slots.push(name);
            if slots.len() > maximum_slots {
                return Err(protection_file_error(
                    "protection target count exceeded its bound",
                ));
            }
        }
        slots.sort();
        Ok(slots)
    }

    // Reads one owner-only file under its exact byte bound.
    fn read_private_file(
        &self,
        path: &Path,
        maximum_bytes: usize,
    ) -> Result<Option<Vec<u8>>, WatchdogError> {
        if maximum_bytes == 0 || maximum_bytes > MAX_TRIP_BYTES {
            return Err(protection_file_error("private file bound is invalid"));
        }
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(protection_file_error("private file could not be opened")),
        };
        validate_private_file(&file, self.owner_user_id, maximum_bytes)?;
        read_private_payload(file, maximum_bytes).map(Some)
    }

    // Writes one same-directory private temporary before atomically replacing its peer.
    fn write_atomic_private_file(&self, path: &Path, payload: &[u8]) -> Result<(), WatchdogError> {
        if payload.is_empty() || payload.len() > MAX_TRIP_BYTES {
            return Err(protection_file_error("private payload bound is invalid"));
        }
        let parent = path
            .parent()
            .ok_or_else(|| protection_file_error("private file parent is missing"))?;
        validate_private_directory_path(parent, self.owner_user_id)?;
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                validate_private_file_metadata(&metadata, self.owner_user_id, MAX_TRIP_BYTES)?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(protection_file_error("private file could not be inspected")),
        }
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| protection_file_error("private file name is invalid"))?;
        let counter = self.temporary_counter.fetch_add(1, Ordering::SeqCst);
        let temporary = parent.join(format!(
            ".{name}.li_watchdog_{}_{}",
            std::process::id(),
            counter
        ));
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(&temporary)
                .map_err(|_| protection_file_error("private temporary could not be created"))?;
            file.write_all(payload)
                .and_then(|_| file.sync_all())
                .map_err(|_| protection_file_error("private payload could not be synchronized"))?;
            drop(file);
            fs::rename(&temporary, path)
                .map_err(|_| protection_file_error("private payload could not be activated"))?;
            sync_private_directory(parent)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
}

// Owns descriptor discovery, native safety baselines, durable latches, and containment.
pub struct LinuxWatchdogProtectionProvider {
    layout: WatchdogLinuxProtectionLayout,
    files: Arc<dyn WatchdogLinuxProtectionFileProvider>,
    host: Arc<dyn WatchdogLinuxHostFileProvider>,
    processes: Arc<dyn WatchdogLinuxProcessProvider>,
    clock: Arc<dyn WatchdogLinuxClock>,
    state: Mutex<LinuxWatchdogProtectionState>,
}

impl LinuxWatchdogProtectionProvider {
    // Creates one protection provider with empty baselines and explicit native dependencies.
    pub fn new(
        layout: WatchdogLinuxProtectionLayout,
        files: Arc<dyn WatchdogLinuxProtectionFileProvider>,
        host: Arc<dyn WatchdogLinuxHostFileProvider>,
        processes: Arc<dyn WatchdogLinuxProcessProvider>,
        clock: Arc<dyn WatchdogLinuxClock>,
    ) -> Self {
        Self {
            layout,
            files,
            host,
            processes,
            clock,
            state: Mutex::new(LinuxWatchdogProtectionState::default()),
        }
    }

    // Creates the complete production Linux descriptor, procfs, pidfd, and clock composition.
    pub fn system() -> Self {
        let host: Arc<dyn WatchdogLinuxHostFileProvider> =
            Arc::new(SystemWatchdogLinuxHostFileProvider);
        let processes = Arc::new(SystemWatchdogLinuxProcessProvider::new(
            WatchdogLinuxProcessLayout::system(),
            host.clone(),
            Arc::new(SystemWatchdogLinuxPidFdProvider),
        ));
        Self::new(
            WatchdogLinuxProtectionLayout::system(),
            Arc::new(SystemWatchdogLinuxProtectionFileProvider::current_user()),
            host,
            processes,
            Arc::new(SystemWatchdogLinuxClock),
        )
    }

    // Discovers changed descriptors and retains missing active slots for continued containment.
    fn discovered_slots(
        &self,
        current: &LinuxWatchdogProtectionState,
    ) -> Result<(BTreeMap<String, LinuxWatchdogProtectionSlot>, Vec<String>), WatchdogError> {
        let keys = self.files.slots(
            &self.layout.protected_placements_root,
            maximum_watchdog_targets(),
        )?;
        if keys.len() > maximum_watchdog_targets() {
            return Err(protection_error(
                "protection target count exceeded its bound",
            ));
        }
        let mut next = current.slots.clone();
        let mut seen = BTreeSet::new();
        let mut changed = Vec::new();
        for key in keys {
            if !valid_slot_name(&key) || !seen.insert(key.clone()) {
                return Err(protection_error(
                    "protection slot identity is invalid or duplicated",
                ));
            }
            let descriptor_path = self.layout.slot_file(&key, PROTECTION_STATE_NAME);
            let Some(payload) = self
                .files
                .read_private_file(&descriptor_path, MAX_DESCRIPTOR_BYTES)?
            else {
                if !next.contains_key(&key) {
                    continue;
                }
                continue;
            };
            let source = String::from_utf8(payload)
                .map_err(|_| protection_error("protection descriptor is not valid UTF-8"))?;
            let target = WatchdogProtectedEngine::parse(&source)?;
            let unchanged = next.get(&key).is_some_and(|slot| slot.target == target);
            if unchanged {
                continue;
            }
            let requires_process = matches!(
                target.phase(),
                WatchdogProtectionPhase::Starting | WatchdogProtectionPhase::Armed
            );
            let process = if requires_process {
                self.processes.bind(&target)?
            } else {
                None
            };
            let may_acknowledge = !requires_process || process.is_some();
            next.insert(
                key.clone(),
                LinuxWatchdogProtectionSlot {
                    target,
                    process,
                    pressure: None,
                    cgroup: None,
                },
            );
            if may_acknowledge {
                changed.push(key);
            }
        }
        next.retain(|key, slot| {
            seen.contains(key)
                || matches!(
                    slot.target.phase(),
                    WatchdogProtectionPhase::Starting | WatchdogProtectionPhase::Armed
                )
        });
        Ok((next, changed))
    }

    // Collects one complete native observation set without partially committing baselines.
    fn collect_observations(
        &self,
        slots: &mut BTreeMap<String, LinuxWatchdogProtectionSlot>,
    ) -> Result<Vec<WatchdogProtectionObservation>, WatchdogError> {
        let has_active = slots.values().any(|slot| {
            matches!(
                slot.target.phase(),
                WatchdogProtectionPhase::Starting | WatchdogProtectionPhase::Armed
            )
        });
        let memory = has_active.then(|| self.memory_input()).transpose()?;
        let pressure = has_active.then(|| self.pressure_totals()).transpose()?;
        let mut observations = Vec::with_capacity(slots.len());
        for (key, slot) in slots.iter_mut() {
            let trip_latched = self
                .files
                .read_private_file(
                    &self.layout.slot_file(key, PROTECTION_TRIP_NAME),
                    MAX_TRIP_BYTES,
                )?
                .is_some();
            if !matches!(
                slot.target.phase(),
                WatchdogProtectionPhase::Starting | WatchdogProtectionPhase::Armed
            ) {
                observations.push(WatchdogProtectionObservation::new(
                    slot.target.clone(),
                    WatchdogProcessState::Exited,
                    WatchdogSafetyInput::default(),
                    trip_latched,
                ));
                continue;
            }
            let process_state = match &slot.process {
                Some(process) => process.state()?,
                None => WatchdogProcessState::Exited,
            };
            let mut safety = memory.expect("active protection memory input");
            if let Some(WatchdogLinuxCapability::Available(current)) = pressure {
                if let Some(previous) = slot.pressure {
                    safety.psi_some_delta_microseconds =
                        monotonic_delta(current.some, previous.some);
                    safety.psi_full_delta_microseconds =
                        monotonic_delta(current.full, previous.full);
                }
                slot.pressure = Some(current);
            }
            let cgroup = slot
                .target
                .cgroup()
                .ok_or_else(|| protection_error("active descriptor has no cgroup identity"))?;
            let current = self.cgroup_events(cgroup)?;
            if let Some(previous) = slot.cgroup {
                safety.cgroup_oom_delta = monotonic_delta(current.oom, previous.oom);
                safety.cgroup_oom_kill_delta = monotonic_delta(current.oom_kill, previous.oom_kill);
                safety.cgroup_oom_group_kill_delta =
                    monotonic_delta(current.oom_group_kill, previous.oom_group_kill);
                safety.cgroup_max_delta = monotonic_delta(current.maximum, previous.maximum);
            }
            slot.cgroup = Some(current);
            observations.push(WatchdogProtectionObservation::new(
                slot.target.clone(),
                process_state,
                safety,
                trip_latched,
            ));
        }
        Ok(observations)
    }

    // Reads exact available and swap bytes required by protection policy.
    fn memory_input(&self) -> Result<WatchdogSafetyInput, WatchdogError> {
        let source = required_kernel_text(
            self.host.read(&self.layout.meminfo, MAX_MEMINFO_BYTES)?,
            "memory counters are unsupported",
        )?;
        parse_memory_input(&source)
    }

    // Reads optional PSI totals without converting unsupported PSI into provider failure.
    fn pressure_totals(&self) -> Result<WatchdogLinuxCapability<PressureTotals>, WatchdogError> {
        match self
            .host
            .read(&self.layout.memory_pressure, MAX_PRESSURE_BYTES)?
        {
            WatchdogLinuxCapability::Available(value) => {
                let source = String::from_utf8(value)
                    .map_err(|_| protection_error("memory pressure is not valid UTF-8"))?;
                parse_pressure_totals(&source).map(WatchdogLinuxCapability::Available)
            }
            WatchdogLinuxCapability::Unsupported => Ok(WatchdogLinuxCapability::Unsupported),
        }
    }

    // Reads one exact cgroup-v2 memory.events snapshot.
    fn cgroup_events(&self, cgroup: &str) -> Result<CgroupEvents, WatchdogError> {
        let source = required_kernel_text(
            self.host.read(
                &Path::new(cgroup).join("memory.events"),
                MAX_CGROUP_EVENTS_BYTES,
            )?,
            "cgroup memory events are unsupported",
        )?;
        parse_cgroup_events(&source)
    }

    // Finds one exact currently observed slot without accepting generation ambiguity.
    fn slot_for_target<'a>(
        state: &'a LinuxWatchdogProtectionState,
        target: &WatchdogProtectedEngine,
    ) -> Result<(&'a str, &'a LinuxWatchdogProtectionSlot), WatchdogError> {
        let matches = state
            .slots
            .iter()
            .filter(|(_, slot)| &slot.target == target)
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(protection_error(
                "protection target is missing or ambiguous",
            ));
        }
        Ok((matches[0].0.as_str(), matches[0].1))
    }

    // Writes exact acknowledgements for every successfully rebound descriptor.
    fn acknowledge_changed(
        &self,
        slots: &BTreeMap<String, LinuxWatchdogProtectionSlot>,
        changed: &[String],
    ) -> Result<(), WatchdogError> {
        for key in changed {
            let target = &slots
                .get(key)
                .ok_or_else(|| protection_error("changed protection slot disappeared"))?
                .target;
            self.write_acknowledgement(key, target)?;
        }
        Ok(())
    }

    // Writes one byte-exact version-one C acknowledgement.
    fn write_acknowledgement(
        &self,
        slot: &str,
        target: &WatchdogProtectedEngine,
    ) -> Result<(), WatchdogError> {
        let phase = protection_phase_name(target.phase());
        let container_id = target.container_id().unwrap_or("-");
        let payload = format!(
            "version=1\ngeneration={}\nphase={}\ncontainer_id={}\n",
            target.generation(),
            phase,
            container_id
        );
        if payload.len() > MAX_ACKNOWLEDGEMENT_BYTES {
            return Err(protection_error(
                "protection acknowledgement exceeds its bound",
            ));
        }
        self.files.write_atomic_private_file(
            &self.layout.slot_file(slot, PROTECTION_ACKNOWLEDGEMENT_NAME),
            payload.as_bytes(),
        )
    }
}

impl WatchdogProtectionProvider for LinuxWatchdogProtectionProvider {
    // Discovers, binds, samples, acknowledges, and atomically commits one target set.
    fn observations(
        &self,
        _sample: &WatchdogSample,
    ) -> Result<Vec<WatchdogProtectionObservation>, WatchdogError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| WatchdogError::StateUnavailable)?;
        let (mut slots, changed) = self.discovered_slots(&state)?;
        validate_protection_slots(&slots)?;
        let observations = self.collect_observations(&mut slots)?;
        self.acknowledge_changed(&slots, &changed)?;
        state.slots = slots;
        Ok(observations)
    }

    // Acknowledges one exact disarmed descriptor idempotently.
    fn acknowledge_disarmed(&self, target: &WatchdogProtectedEngine) -> Result<(), WatchdogError> {
        if target.phase() != WatchdogProtectionPhase::Disarmed {
            return Err(protection_error(
                "only a disarmed descriptor may use the disarm acknowledgement",
            ));
        }
        let state = self
            .state
            .lock()
            .map_err(|_| WatchdogError::StateUnavailable)?;
        let (slot, _) = Self::slot_for_target(&state, target)?;
        self.write_acknowledgement(slot, target)
    }

    // Writes one byte-exact durable C trip before containment can signal a process.
    fn latch_trip(
        &self,
        target: &WatchdogProtectedEngine,
        action: WatchdogSafetyAction,
        reason: &'static str,
        input: WatchdogSafetyInput,
    ) -> Result<(), WatchdogError> {
        if !matches!(reason, "protected_process_exited" | "cgroup_oom_kill") {
            return Err(protection_error(
                "trip reason is outside the closed vocabulary",
            ));
        }
        let state = self
            .state
            .lock()
            .map_err(|_| WatchdogError::StateUnavailable)?;
        let (slot, _) = Self::slot_for_target(&state, target)?;
        let container_id = target
            .container_id()
            .ok_or_else(|| protection_error("trip target has no container identity"))?;
        let timestamp = self.clock.clocks()?.unix_milliseconds();
        let action = match action {
            WatchdogSafetyAction::Stop => "stop",
            WatchdogSafetyAction::Kill => "kill",
        };
        let payload = format!(
            "{{\n  \"schema_version\": 1,\n  \"timestamp_unix_ms\": {},\n  \"generation\": \"{}\",\n  \"container_id\": \"{}\",\n  \"action\": \"{}\",\n  \"reason\": \"{}\",\n  \"available_bytes\": {},\n  \"swap_used_bytes\": {}\n}}\n",
            timestamp,
            target.generation(),
            container_id,
            action,
            reason,
            input.available_bytes,
            input.swap_used_bytes
        );
        self.files.write_atomic_private_file(
            &self.layout.slot_file(slot, PROTECTION_TRIP_NAME),
            payload.as_bytes(),
        )
    }

    // Signals the exact pidfd, escalates once, and empties only its bound cgroup.
    fn contain(
        &self,
        target: &WatchdogProtectedEngine,
        action: WatchdogSafetyAction,
        grace_milliseconds: u32,
    ) -> Result<bool, WatchdogError> {
        if !(1..=30_000).contains(&grace_milliseconds) {
            return Err(protection_error("containment grace is outside its bound"));
        }
        let state = self
            .state
            .lock()
            .map_err(|_| WatchdogError::StateUnavailable)?;
        let (_, slot) = Self::slot_for_target(&state, target)?;
        let cgroup = target
            .cgroup()
            .ok_or_else(|| protection_error("containment target has no cgroup identity"))?;
        if let Some(process) = &slot.process {
            let signal = match action {
                WatchdogSafetyAction::Stop => WatchdogLinuxSignal::Terminate,
                WatchdogSafetyAction::Kill => WatchdogLinuxSignal::Kill,
            };
            if process.signal(signal).is_ok() {
                let first_wait = match action {
                    WatchdogSafetyAction::Stop => {
                        Duration::from_millis(u64::from(grace_milliseconds))
                    }
                    WatchdogSafetyAction::Kill => {
                        Duration::from_millis(CONTAINMENT_ESCALATION_MILLISECONDS)
                    }
                };
                if !process.wait_for_exit(first_wait).unwrap_or(false) {
                    let _ = process.signal(WatchdogLinuxSignal::Kill);
                    let _ = process
                        .wait_for_exit(Duration::from_millis(CONTAINMENT_ESCALATION_MILLISECONDS));
                }
            }
        }
        if self.processes.cgroup_is_empty(cgroup)? {
            return Ok(true);
        }
        self.processes.kill_cgroup_members(cgroup)?;
        for _ in 0..CGROUP_EMPTY_ATTEMPTS {
            if self.processes.cgroup_is_empty(cgroup)? {
                return Ok(true);
            }
            self.processes
                .wait(Duration::from_millis(CGROUP_EMPTY_INTERVAL_MILLISECONDS));
        }
        self.processes.cgroup_is_empty(cgroup)
    }
}

// Stores one target's exact bound process and independent cumulative safety baselines.
#[derive(Clone)]
struct LinuxWatchdogProtectionSlot {
    target: WatchdogProtectedEngine,
    process: Option<Arc<dyn WatchdogLinuxPidFd>>,
    pressure: Option<PressureTotals>,
    cgroup: Option<CgroupEvents>,
}

// Owns every active or descriptor-present Linux protection slot.
#[derive(Clone, Default)]
struct LinuxWatchdogProtectionState {
    slots: BTreeMap<String, LinuxWatchdogProtectionSlot>,
}

// Stores monotonic Linux memory-pressure totals.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PressureTotals {
    some: u64,
    full: u64,
}

// Stores monotonic cgroup-v2 memory event totals.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CgroupEvents {
    oom: u64,
    oom_kill: u64,
    oom_group_kill: u64,
    maximum: u64,
}

// Reads one private regular file completely under its metadata-verified bound.
fn read_private_payload(file: File, maximum_bytes: usize) -> Result<Vec<u8>, WatchdogError> {
    let mut payload = Vec::new();
    file.take(maximum_bytes as u64 + 1)
        .read_to_end(&mut payload)
        .map_err(|_| protection_file_error("private file could not be read"))?;
    if payload.len() > maximum_bytes {
        return Err(protection_file_error(
            "private file exceeded its byte bound",
        ));
    }
    Ok(payload)
}

// Requires one no-follow descriptor to retain owner, mode, link, type, and size identity.
fn validate_private_file(
    file: &File,
    owner_user_id: u32,
    maximum_bytes: usize,
) -> Result<(), WatchdogError> {
    let metadata = file
        .metadata()
        .map_err(|_| protection_file_error("private file metadata is unavailable"))?;
    validate_private_file_metadata(&metadata, owner_user_id, maximum_bytes)
}

// Requires one owner-only single-link regular file under its exact bound.
fn validate_private_file_metadata(
    metadata: &fs::Metadata,
    owner_user_id: u32,
    maximum_bytes: usize,
) -> Result<(), WatchdogError> {
    if !metadata.file_type().is_file()
        || metadata.uid() != owner_user_id
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
        || metadata.len() > maximum_bytes as u64
    {
        return Err(protection_file_error(
            "private file ownership, mode, link, type, or size is unsafe",
        ));
    }
    Ok(())
}

// Requires one exact owner-only directory without following its final component.
fn validate_private_directory_path(path: &Path, owner_user_id: u32) -> Result<(), WatchdogError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| protection_file_error("private directory could not be inspected"))?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != owner_user_id
        || metadata.mode() & 0o077 != 0
    {
        return Err(protection_file_error(
            "private directory ownership, mode, or type is unsafe",
        ));
    }
    Ok(())
}

// Synchronizes one private directory after a durable rename.
fn sync_private_directory(path: &Path) -> Result<(), WatchdogError> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| protection_file_error("private directory could not be opened safely"))?;
    directory
        .sync_all()
        .map_err(|_| protection_file_error("private directory could not be synchronized"))
}

// Converts one required kernel capability into strict UTF-8 text.
fn required_kernel_text(
    capability: WatchdogLinuxCapability<Vec<u8>>,
    reason: &'static str,
) -> Result<String, WatchdogError> {
    match capability {
        WatchdogLinuxCapability::Available(value) => String::from_utf8(value)
            .map_err(|_| protection_error("kernel counter is not valid UTF-8")),
        WatchdogLinuxCapability::Unsupported => Err(protection_error(reason)),
    }
}

// Parses available and swap bytes from one strict procfs meminfo document.
fn parse_memory_input(source: &str) -> Result<WatchdogSafetyInput, WatchdogError> {
    let mut values = BTreeMap::new();
    for line in source.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let fields = value.split_whitespace().collect::<Vec<_>>();
        if fields.is_empty() || fields.len() > 2 || (fields.len() == 2 && fields[1] != "kB") {
            return Err(protection_error("memory counter is malformed"));
        }
        let value = fields[0]
            .parse::<u64>()
            .map_err(|_| protection_error("memory counter is malformed"))?;
        if values.insert(name, value).is_some() {
            return Err(protection_error("memory counter is duplicated"));
        }
    }
    let available = named_value(&values, "MemAvailable")?;
    let swap_total = named_value(&values, "SwapTotal")?;
    let swap_free = named_value(&values, "SwapFree")?;
    if available == 0 || swap_free > swap_total {
        return Err(protection_error("memory counters are invalid"));
    }
    Ok(WatchdogSafetyInput {
        available_bytes: available
            .checked_mul(1_024)
            .ok_or_else(|| protection_error("available memory overflowed"))?,
        swap_used_bytes: swap_total
            .saturating_sub(swap_free)
            .checked_mul(1_024)
            .ok_or_else(|| protection_error("swap use overflowed"))?,
        ..WatchdogSafetyInput::default()
    })
}

// Returns one required named native counter.
fn named_value(values: &BTreeMap<&str, u64>, name: &'static str) -> Result<u64, WatchdogError> {
    values
        .get(name)
        .copied()
        .ok_or_else(|| protection_error("required native counter is missing"))
}

// Parses exact some and full PSI totals without using moving averages as safety evidence.
fn parse_pressure_totals(source: &str) -> Result<PressureTotals, WatchdogError> {
    let mut some = None;
    let mut full = None;
    for line in source.lines() {
        let mut fields = line.split_whitespace();
        let Some(kind) = fields.next() else {
            continue;
        };
        let total = fields
            .find_map(|field| field.strip_prefix("total="))
            .ok_or_else(|| protection_error("memory pressure total is missing"))?
            .parse::<u64>()
            .map_err(|_| protection_error("memory pressure total is malformed"))?;
        match kind {
            "some" if some.replace(total).is_none() => {}
            "full" if full.replace(total).is_none() => {}
            "some" | "full" => return Err(protection_error("memory pressure total is duplicated")),
            _ => {}
        }
    }
    Ok(PressureTotals {
        some: some.ok_or_else(|| protection_error("partial pressure total is missing"))?,
        full: full.ok_or_else(|| protection_error("full pressure total is missing"))?,
    })
}

// Parses the closed cgroup-v2 memory.events counter set.
fn parse_cgroup_events(source: &str) -> Result<CgroupEvents, WatchdogError> {
    let mut values = BTreeMap::new();
    for line in source.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() != 2 {
            return Err(protection_error("cgroup memory event is malformed"));
        }
        let value = fields[1]
            .parse::<u64>()
            .map_err(|_| protection_error("cgroup memory event is malformed"))?;
        if values.insert(fields[0], value).is_some() {
            return Err(protection_error("cgroup memory event is duplicated"));
        }
    }
    Ok(CgroupEvents {
        oom: named_value(&values, "oom")?,
        oom_kill: named_value(&values, "oom_kill")?,
        oom_group_kill: values.get("oom_group_kill").copied().unwrap_or(0),
        maximum: named_value(&values, "max")?,
    })
}

// Converts one monotonic cumulative counter into a reset-safe interval delta.
fn monotonic_delta(current: u64, previous: u64) -> u64 {
    current.checked_sub(previous).unwrap_or(0)
}

// Requires a bounded slot set with globally unique protection generations.
fn validate_protection_slots(
    slots: &BTreeMap<String, LinuxWatchdogProtectionSlot>,
) -> Result<(), WatchdogError> {
    let generations = slots
        .values()
        .map(|slot| slot.target.generation())
        .collect::<BTreeSet<_>>();
    if slots.len() > maximum_watchdog_targets() || generations.len() != slots.len() {
        return Err(protection_error(
            "protection slots are duplicated or exceed their bound",
        ));
    }
    Ok(())
}

// Returns the exact existing version-one acknowledgement phase vocabulary.
fn protection_phase_name(phase: WatchdogProtectionPhase) -> &'static str {
    match phase {
        WatchdogProtectionPhase::Pending => "pending",
        WatchdogProtectionPhase::Starting => "starting",
        WatchdogProtectionPhase::Armed => "armed",
        WatchdogProtectionPhase::Disarmed => "disarmed",
    }
}

// Returns whether one protection slot uses the established 128-bit lowercase identity.
fn valid_slot_name(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

// Rejects relative, traversing, NUL-containing, or unbounded protection paths.
fn validate_protection_path(path: &Path) -> Result<(), WatchdogError> {
    let bytes = path.as_os_str().as_bytes();
    if !path.is_absolute()
        || bytes.is_empty()
        || bytes.len() > MAX_NATIVE_PATH_BYTES
        || bytes.contains(&0)
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(WatchdogError::InvalidContract {
            reason: "Linux Watchdog protection path is invalid",
        });
    }
    Ok(())
}

// Creates one stable redacted Linux protection filesystem failure.
const fn protection_file_error(reason: &'static str) -> WatchdogError {
    WatchdogError::provider("Linux protection filesystem", reason)
}

// Creates one stable redacted Linux protection observation or containment failure.
const fn protection_error(reason: &'static str) -> WatchdogError {
    WatchdogError::provider("Linux protection", reason)
}
