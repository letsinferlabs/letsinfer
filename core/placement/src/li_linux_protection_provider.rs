// SPDX-License-Identifier: AGPL-3.0-only

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use getrandom::fill;
use li_core_interface::{Placement, TechnicalName};

use crate::li_linux_placement_executor::linux_placement_container_name;
use crate::{
    LinuxPlacementProtectedTargetProvider, LinuxPlacementProtectionProvider,
    LinuxProtectedProcessIdentity, PlacementError, PlacementProtectedTarget,
    PlacementProtectionGeneration, PlacementProtectionPhase, PlacementProtectionStatus,
};

const PROTECTION_ROOT_NAME: &str = "protected-placements";
const PROTECTION_STATE_NAME: &str = "protected-placement.state";
const PROTECTION_ACK_NAME: &str = "protected-placement.ack";
const PROTECTION_TRIP_NAME: &str = "protection-trip.json";
const MAX_DESCRIPTOR_BYTES: usize = 4_096;
const MAX_ACKNOWLEDGEMENT_BYTES: usize = 512;
const MAX_TRIP_BYTES: usize = 16_384;

// Defines exact private filesystem operations used by Watchdog coordination.
pub trait LinuxProtectionIo: Send + Sync {
    // Creates or validates one private owner-only directory.
    fn ensure_private_directory(
        &self,
        path: &Path,
        owner_user_id: u32,
    ) -> Result<(), PlacementError>;

    // Atomically replaces one private regular file and syncs its directory.
    fn write_atomic_private_file(
        &self,
        path: &Path,
        payload: &[u8],
        owner_user_id: u32,
    ) -> Result<(), PlacementError>;

    // Reads one bounded private regular file or reports exact absence.
    fn read_private_file(
        &self,
        path: &Path,
        maximum_bytes: usize,
        owner_user_id: u32,
    ) -> Result<Option<Vec<u8>>, PlacementError>;

    // Removes one private regular file and reports whether it existed.
    fn remove_private_file(&self, path: &Path, owner_user_id: u32) -> Result<bool, PlacementError>;

    // Removes one empty private directory and reports whether it existed.
    fn remove_private_directory(
        &self,
        path: &Path,
        owner_user_id: u32,
    ) -> Result<bool, PlacementError>;

    // Waits one bounded polling interval.
    fn wait(&self, duration: Duration);
}

// Supplies cryptographically unpredictable protection generations.
pub trait PlacementProtectionGenerationProvider: Send + Sync {
    // Returns one new canonical 128-bit generation.
    fn generation(&self) -> Result<PlacementProtectionGeneration, PlacementError>;
}

// Reads operating-system entropy for production protection generations.
#[derive(Default)]
pub struct SystemProtectionGenerationProvider;

impl PlacementProtectionGenerationProvider for SystemProtectionGenerationProvider {
    // Returns one lowercase generation from 128 bits of operating-system entropy.
    fn generation(&self) -> Result<PlacementProtectionGeneration, PlacementError> {
        let mut bytes = [0_u8; 16];
        fill(&mut bytes).map_err(|_| PlacementError::ProtectionUnsafe)?;
        let value = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        PlacementProtectionGeneration::parse(&value)
    }
}

// Performs owner-checked, no-follow, durable filesystem operations.
#[derive(Default)]
pub struct SystemLinuxProtectionIo {
    temporary_counter: AtomicU64,
}

impl LinuxProtectionIo for SystemLinuxProtectionIo {
    // Creates or validates one private directory without following a symlink.
    fn ensure_private_directory(
        &self,
        path: &Path,
        owner_user_id: u32,
    ) -> Result<(), PlacementError> {
        match fs::symlink_metadata(path) {
            Ok(metadata) => validate_private_directory(&metadata, owner_user_id),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(path).map_err(|_| PlacementError::ProtectionUnsafe)?;
                fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                    .map_err(|_| PlacementError::ProtectionUnsafe)?;
                let metadata =
                    fs::symlink_metadata(path).map_err(|_| PlacementError::ProtectionUnsafe)?;
                validate_private_directory(&metadata, owner_user_id)
            }
            Err(_) => Err(PlacementError::ProtectionUnsafe),
        }
    }

    // Writes one private file through an exclusive same-directory temporary.
    fn write_atomic_private_file(
        &self,
        path: &Path,
        payload: &[u8],
        owner_user_id: u32,
    ) -> Result<(), PlacementError> {
        if payload.is_empty() || payload.len() > MAX_DESCRIPTOR_BYTES {
            return Err(PlacementError::ProtectionUnsafe);
        }
        let parent = path.parent().ok_or(PlacementError::ProtectionUnsafe)?;
        self.ensure_private_directory(parent, owner_user_id)?;
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                validate_private_file_metadata(&metadata, owner_user_id, MAX_DESCRIPTOR_BYTES)?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(PlacementError::ProtectionUnsafe),
        }
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or(PlacementError::ProtectionUnsafe)?;
        let counter = self.temporary_counter.fetch_add(1, Ordering::SeqCst);
        let temporary = parent.join(format!(
            ".{name}.li_incoming_{}_{}",
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
                .map_err(|_| PlacementError::ProtectionUnsafe)?;
            file.write_all(payload)
                .and_then(|_| file.sync_all())
                .map_err(|_| PlacementError::ProtectionUnsafe)?;
            drop(file);
            fs::rename(&temporary, path).map_err(|_| PlacementError::ProtectionUnsafe)?;
            sync_directory(parent)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    // Reads one bounded private file through a no-follow descriptor.
    fn read_private_file(
        &self,
        path: &Path,
        maximum_bytes: usize,
        owner_user_id: u32,
    ) -> Result<Option<Vec<u8>>, PlacementError> {
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(PlacementError::ProtectionUnsafe),
        };
        let metadata = file
            .metadata()
            .map_err(|_| PlacementError::ProtectionUnsafe)?;
        validate_private_file_metadata(&metadata, owner_user_id, maximum_bytes)?;
        let mut payload = Vec::with_capacity(metadata.len() as usize);
        file.take(maximum_bytes as u64 + 1)
            .read_to_end(&mut payload)
            .map_err(|_| PlacementError::ProtectionUnsafe)?;
        if payload.len() > maximum_bytes {
            return Err(PlacementError::ProtectionUnsafe);
        }
        Ok(Some(payload))
    }

    // Removes one validated private file without following a symlink.
    fn remove_private_file(&self, path: &Path, owner_user_id: u32) -> Result<bool, PlacementError> {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(_) => return Err(PlacementError::ProtectionUnsafe),
        };
        validate_private_file_metadata(&metadata, owner_user_id, usize::MAX)?;
        fs::remove_file(path).map_err(|_| PlacementError::ProtectionUnsafe)?;
        sync_directory(path.parent().ok_or(PlacementError::ProtectionUnsafe)?)?;
        Ok(true)
    }

    // Removes one exact empty private directory and syncs its parent.
    fn remove_private_directory(
        &self,
        path: &Path,
        owner_user_id: u32,
    ) -> Result<bool, PlacementError> {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(_) => return Err(PlacementError::ProtectionUnsafe),
        };
        validate_private_directory(&metadata, owner_user_id)?;
        fs::remove_dir(path).map_err(|_| PlacementError::ProtectionUnsafe)?;
        sync_directory(path.parent().ok_or(PlacementError::ProtectionUnsafe)?)?;
        Ok(true)
    }

    // Sleeps only for the caller-supplied bounded acknowledgement interval.
    fn wait(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

// Coordinates exact protection descriptors with the resident Rust Watchdog.
pub struct FilesystemLinuxPlacementProtectionProvider {
    protected_placements_root: PathBuf,
    owner_user_id: u32,
    acknowledgement_attempts: u16,
    acknowledgement_interval: Duration,
    io: Arc<dyn LinuxProtectionIo>,
    generations: Arc<dyn PlacementProtectionGenerationProvider>,
}

impl FilesystemLinuxPlacementProtectionProvider {
    // Creates one provider rooted at the exact managed protection directory.
    pub fn new(
        protected_placements_root: PathBuf,
        owner_user_id: u32,
        acknowledgement_attempts: u16,
        acknowledgement_interval: Duration,
        io: Arc<dyn LinuxProtectionIo>,
        generations: Arc<dyn PlacementProtectionGenerationProvider>,
    ) -> Result<Self, PlacementError> {
        if !protected_placements_root.is_absolute()
            || protected_placements_root
                .file_name()
                .and_then(|value| value.to_str())
                != Some(PROTECTION_ROOT_NAME)
            || acknowledgement_attempts == 0
            || acknowledgement_attempts > 1_000
            || acknowledgement_interval.is_zero()
            || acknowledgement_interval > Duration::from_secs(1)
        {
            return Err(PlacementError::InvalidRequest {
                reason: "Linux protection provider configuration is invalid",
            });
        }
        Ok(Self {
            protected_placements_root,
            owner_user_id,
            acknowledgement_attempts,
            acknowledgement_interval,
            io,
            generations,
        })
    }

    // Returns the exact private slot for one placement identity.
    fn slot_root(&self, placement: &Placement) -> PathBuf {
        self.protected_placements_root
            .join(placement.placement_id().as_str())
    }

    // Returns the state, acknowledgement, and trip paths for one exact slot.
    fn paths(&self, placement: &Placement) -> (PathBuf, PathBuf, PathBuf) {
        let root = self.slot_root(placement);
        (
            root.join(PROTECTION_STATE_NAME),
            root.join(PROTECTION_ACK_NAME),
            root.join(PROTECTION_TRIP_NAME),
        )
    }

    // Creates or validates the private root and one placement slot.
    fn prepare_slot(&self, placement: &Placement) -> Result<(), PlacementError> {
        self.io
            .ensure_private_directory(&self.protected_placements_root, self.owner_user_id)?;
        self.io
            .ensure_private_directory(&self.slot_root(placement), self.owner_user_id)
    }

    // Publishes one exact descriptor and waits for matching Watchdog acknowledgement.
    fn publish(
        &self,
        placement: &Placement,
        generation: &PlacementProtectionGeneration,
        phase: PlacementProtectionPhase,
        process: Option<&LinuxProtectedProcessIdentity>,
    ) -> Result<(), PlacementError> {
        self.prepare_slot(placement)?;
        let (state_path, acknowledgement_path, _) = self.paths(placement);
        let payload = protection_descriptor(placement, generation, phase, process)?;
        self.io
            .write_atomic_private_file(&state_path, payload.as_bytes(), self.owner_user_id)?;
        self.await_acknowledgement(
            &acknowledgement_path,
            generation,
            phase,
            process.map(LinuxProtectedProcessIdentity::container_id),
        )
    }

    // Waits a bounded number of intervals for one exact acknowledgement.
    fn await_acknowledgement(
        &self,
        path: &Path,
        generation: &PlacementProtectionGeneration,
        phase: PlacementProtectionPhase,
        container_id: Option<&li_core_interface::Sha256Digest>,
    ) -> Result<(), PlacementError> {
        for attempt in 0..self.acknowledgement_attempts {
            if let Some(payload) =
                self.io
                    .read_private_file(path, MAX_ACKNOWLEDGEMENT_BYTES, self.owner_user_id)?
            {
                if acknowledgement_matches(&payload, generation, phase, container_id) {
                    return Ok(());
                }
            }
            if attempt + 1 < self.acknowledgement_attempts {
                self.io.wait(self.acknowledgement_interval);
            }
        }
        Err(PlacementError::ProtectionUnsafe)
    }
}

impl LinuxPlacementProtectionProvider for FilesystemLinuxPlacementProtectionProvider {
    // Publishes pending only when no durable trip is present.
    fn begin(
        &self,
        placement: &Placement,
    ) -> Result<PlacementProtectionGeneration, PlacementError> {
        self.prepare_slot(placement)?;
        let (_, acknowledgement_path, trip_path) = self.paths(placement);
        if self
            .io
            .read_private_file(&trip_path, MAX_TRIP_BYTES, self.owner_user_id)?
            .is_some()
        {
            return Err(PlacementError::ProtectionUnsafe);
        }
        self.io
            .remove_private_file(&acknowledgement_path, self.owner_user_id)?;
        let generation = self.generations.generation()?;
        self.publish(
            placement,
            &generation,
            PlacementProtectionPhase::Pending,
            None,
        )?;
        Ok(generation)
    }

    // Publishes the exact starting process identity and waits for pidfd binding.
    fn bind_starting(
        &self,
        placement: &Placement,
        generation: &PlacementProtectionGeneration,
        process: &LinuxProtectedProcessIdentity,
    ) -> Result<(), PlacementError> {
        require_process_name(placement, process)?;
        self.publish(
            placement,
            generation,
            PlacementProtectionPhase::Starting,
            Some(process),
        )
    }

    // Publishes armed only after the same exact process passed readiness.
    fn arm(
        &self,
        placement: &Placement,
        generation: &PlacementProtectionGeneration,
        process: &LinuxProtectedProcessIdentity,
    ) -> Result<(), PlacementError> {
        require_process_name(placement, process)?;
        self.publish(
            placement,
            generation,
            PlacementProtectionPhase::Armed,
            Some(process),
        )
    }

    // Publishes disarmed with the existing generation or one new generation.
    fn disarm(&self, placement: &Placement) -> Result<PlacementProtectionStatus, PlacementError> {
        self.prepare_slot(placement)?;
        let (state_path, _, _) = self.paths(placement);
        let generation = match self.io.read_private_file(
            &state_path,
            MAX_DESCRIPTOR_BYTES,
            self.owner_user_id,
        )? {
            Some(payload) => {
                let descriptor = parse_descriptor(&payload)?;
                if descriptor.container_name != linux_placement_container_name(placement)? {
                    return Err(PlacementError::ProtectionUnsafe);
                }
                descriptor.generation
            }
            None => self.generations.generation()?,
        };
        self.publish(
            placement,
            &generation,
            PlacementProtectionPhase::Disarmed,
            None,
        )?;
        self.status(placement, None)
    }

    // Requires state and acknowledgement to agree before returning protection status.
    fn status(
        &self,
        placement: &Placement,
        process: Option<&LinuxProtectedProcessIdentity>,
    ) -> Result<PlacementProtectionStatus, PlacementError> {
        let (state_path, acknowledgement_path, trip_path) = self.paths(placement);
        let trip_latched = self
            .io
            .read_private_file(&trip_path, MAX_TRIP_BYTES, self.owner_user_id)?
            .is_some();
        let Some(state_payload) =
            self.io
                .read_private_file(&state_path, MAX_DESCRIPTOR_BYTES, self.owner_user_id)?
        else {
            return Ok(PlacementProtectionStatus::new(
                PlacementProtectionPhase::Unconfigured,
                trip_latched,
            ));
        };
        let descriptor = parse_descriptor(&state_payload)?;
        if descriptor.container_name != linux_placement_container_name(placement)? {
            return Err(PlacementError::ProtectionUnsafe);
        }
        if let Some(expected) = process {
            if descriptor
                .process
                .as_ref()
                .is_some_and(|value| value != expected)
            {
                return Err(PlacementError::ProtectionUnsafe);
            }
        }
        let acknowledgement = self
            .io
            .read_private_file(
                &acknowledgement_path,
                MAX_ACKNOWLEDGEMENT_BYTES,
                self.owner_user_id,
            )?
            .ok_or(PlacementError::ProtectionUnsafe)?;
        if !acknowledgement_matches(
            &acknowledgement,
            &descriptor.generation,
            descriptor.phase,
            descriptor
                .process
                .as_ref()
                .map(LinuxProtectedProcessIdentity::container_id),
        ) {
            return Err(PlacementError::ProtectionUnsafe);
        }
        Ok(PlacementProtectionStatus::new(
            descriptor.phase,
            trip_latched,
        ))
    }

    // Removes one exact private trip file and syncs the slot.
    fn acknowledge_trip(&self, placement: &Placement) -> Result<bool, PlacementError> {
        let (_, _, trip_path) = self.paths(placement);
        self.io.remove_private_file(&trip_path, self.owner_user_id)
    }

    // Removes only a disarmed or unconfigured empty protection slot.
    fn retire(&self, placement: &Placement) -> Result<(), PlacementError> {
        let status = self.status(placement, None)?;
        if status.trip_latched()
            || !matches!(
                status.phase(),
                PlacementProtectionPhase::Unconfigured | PlacementProtectionPhase::Disarmed
            )
        {
            return Err(PlacementError::ProtectionUnsafe);
        }
        let (state_path, acknowledgement_path, trip_path) = self.paths(placement);
        if self
            .io
            .read_private_file(&trip_path, MAX_TRIP_BYTES, self.owner_user_id)?
            .is_some()
        {
            return Err(PlacementError::ProtectionUnsafe);
        }
        self.io
            .remove_private_file(&state_path, self.owner_user_id)?;
        self.io
            .remove_private_file(&acknowledgement_path, self.owner_user_id)?;
        self.io
            .remove_private_directory(&self.slot_root(placement), self.owner_user_id)?;
        Ok(())
    }
}

impl LinuxPlacementProtectedTargetProvider for FilesystemLinuxPlacementProtectionProvider {
    // Reads one exact acknowledged descriptor and exposes only an untripped active process.
    fn active_target(
        &self,
        placement: &Placement,
    ) -> Result<Option<PlacementProtectedTarget>, PlacementError> {
        let (state_path, _, _) = self.paths(placement);
        let Some(payload) =
            self.io
                .read_private_file(&state_path, MAX_DESCRIPTOR_BYTES, self.owner_user_id)?
        else {
            return Ok(None);
        };
        let descriptor = parse_descriptor(&payload)?;
        if descriptor.container_name != linux_placement_container_name(placement)? {
            return Err(PlacementError::ProtectionUnsafe);
        }
        let Some(process) = descriptor.process else {
            return Ok(None);
        };
        let status = self.status(placement, Some(&process))?;
        if status.trip_latched()
            || !matches!(
                status.phase(),
                PlacementProtectionPhase::Starting | PlacementProtectionPhase::Armed
            )
        {
            return Ok(None);
        }
        PlacementProtectedTarget::new(descriptor.generation, descriptor.phase, process).map(Some)
    }
}

// Stores one parsed protection descriptor after strict validation.
struct ProtectionDescriptor {
    generation: PlacementProtectionGeneration,
    phase: PlacementProtectionPhase,
    container_name: TechnicalName,
    process: Option<LinuxProtectedProcessIdentity>,
}

// Requires one process identity to use the placement's exact container name.
fn require_process_name(
    placement: &Placement,
    process: &LinuxProtectedProcessIdentity,
) -> Result<(), PlacementError> {
    if process.container_name() != &linux_placement_container_name(placement)? {
        return Err(PlacementError::ProtectionUnsafe);
    }
    Ok(())
}

// Encodes one exact version-1 descriptor understood by the resident Watchdog.
fn protection_descriptor(
    placement: &Placement,
    generation: &PlacementProtectionGeneration,
    phase: PlacementProtectionPhase,
    process: Option<&LinuxProtectedProcessIdentity>,
) -> Result<String, PlacementError> {
    let needs_process = matches!(
        phase,
        PlacementProtectionPhase::Starting | PlacementProtectionPhase::Armed
    );
    if needs_process != process.is_some() || matches!(phase, PlacementProtectionPhase::Unconfigured)
    {
        return Err(PlacementError::ProtectionUnsafe);
    }
    if let Some(process) = process {
        require_process_name(placement, process)?;
    }
    let name = linux_placement_container_name(placement)?;
    let phase = protection_phase_name(phase)?;
    let (container_id, process_id, start_ticks, boot_id, cgroup) = match process {
        Some(process) => (
            process.container_id().as_str().to_string(),
            process.process_id().to_string(),
            process.process_start_ticks().to_string(),
            process.boot_id().as_str().to_string(),
            process.cgroup().to_string(),
        ),
        None => (
            "-".to_string(),
            "-".to_string(),
            "-".to_string(),
            "-".to_string(),
            "-".to_string(),
        ),
    };
    Ok(format!(
        "version=1\ngeneration={}\nphase={}\ncontainer_name={}\ncontainer_id={}\npid={}\nstart_ticks={}\nboot_id={}\ncgroup={}\n",
        generation.as_str(),
        phase,
        name.as_str(),
        container_id,
        process_id,
        start_ticks,
        boot_id,
        cgroup
    ))
}

// Parses one strict version-1 protection descriptor.
fn parse_descriptor(payload: &[u8]) -> Result<ProtectionDescriptor, PlacementError> {
    let values = parse_lines(payload, 9)?;
    if value(&values, "version")? != "1" {
        return Err(PlacementError::ProtectionUnsafe);
    }
    let generation = PlacementProtectionGeneration::parse(value(&values, "generation")?)?;
    let phase = protection_phase(value(&values, "phase")?)?;
    let container_name = TechnicalName::parse(value(&values, "container_name")?)
        .map_err(|_| PlacementError::ProtectionUnsafe)?;
    let needs_process = matches!(
        phase,
        PlacementProtectionPhase::Starting | PlacementProtectionPhase::Armed
    );
    let process = if needs_process {
        Some(LinuxProtectedProcessIdentity::new(
            container_name.clone(),
            li_core_interface::Sha256Digest::parse(value(&values, "container_id")?)
                .map_err(|_| PlacementError::ProtectionUnsafe)?,
            value(&values, "pid")?
                .parse()
                .map_err(|_| PlacementError::ProtectionUnsafe)?,
            value(&values, "start_ticks")?
                .parse()
                .map_err(|_| PlacementError::ProtectionUnsafe)?,
            li_core_interface::BootId::parse(value(&values, "boot_id")?)
                .map_err(|_| PlacementError::ProtectionUnsafe)?,
            value(&values, "cgroup")?,
        )?)
    } else {
        if ["container_id", "pid", "start_ticks", "boot_id", "cgroup"]
            .iter()
            .any(|key| value(&values, key).ok() != Some("-"))
        {
            return Err(PlacementError::ProtectionUnsafe);
        }
        None
    };
    Ok(ProtectionDescriptor {
        generation,
        phase,
        container_name,
        process,
    })
}

// Returns whether one acknowledgement exactly matches the published descriptor.
fn acknowledgement_matches(
    payload: &[u8],
    generation: &PlacementProtectionGeneration,
    phase: PlacementProtectionPhase,
    container_id: Option<&li_core_interface::Sha256Digest>,
) -> bool {
    let Ok(values) = parse_lines(payload, 4) else {
        return false;
    };
    value(&values, "version").ok() == Some("1")
        && value(&values, "generation").ok() == Some(generation.as_str())
        && value(&values, "phase").ok() == protection_phase_name(phase).ok()
        && value(&values, "container_id").ok()
            == Some(container_id.map_or("-", li_core_interface::Sha256Digest::as_str))
}

// Parses one exact set of newline-delimited key-value fields.
fn parse_lines(
    payload: &[u8],
    expected_fields: usize,
) -> Result<Vec<(String, String)>, PlacementError> {
    let text = std::str::from_utf8(payload).map_err(|_| PlacementError::ProtectionUnsafe)?;
    if !text.ends_with('\n') {
        return Err(PlacementError::ProtectionUnsafe);
    }
    let mut values = Vec::new();
    for line in text.lines() {
        let (key, value) = line
            .split_once('=')
            .ok_or(PlacementError::ProtectionUnsafe)?;
        if key.is_empty()
            || value.contains('=')
            || values.iter().any(|(existing, _)| existing == key)
        {
            return Err(PlacementError::ProtectionUnsafe);
        }
        values.push((key.to_string(), value.to_string()));
    }
    if values.len() != expected_fields {
        return Err(PlacementError::ProtectionUnsafe);
    }
    Ok(values)
}

// Returns one required parsed value by exact key.
fn value<'a>(values: &'a [(String, String)], key: &str) -> Result<&'a str, PlacementError> {
    values
        .iter()
        .find(|(candidate, _)| candidate == key)
        .map(|(_, value)| value.as_str())
        .ok_or(PlacementError::ProtectionUnsafe)
}

// Returns the descriptor name for one publishable protection phase.
fn protection_phase_name(phase: PlacementProtectionPhase) -> Result<&'static str, PlacementError> {
    match phase {
        PlacementProtectionPhase::Pending => Ok("pending"),
        PlacementProtectionPhase::Starting => Ok("starting"),
        PlacementProtectionPhase::Armed => Ok("armed"),
        PlacementProtectionPhase::Disarmed => Ok("disarmed"),
        PlacementProtectionPhase::Unconfigured => Err(PlacementError::ProtectionUnsafe),
    }
}

// Parses one exact descriptor protection phase.
fn protection_phase(value: &str) -> Result<PlacementProtectionPhase, PlacementError> {
    match value {
        "pending" => Ok(PlacementProtectionPhase::Pending),
        "starting" => Ok(PlacementProtectionPhase::Starting),
        "armed" => Ok(PlacementProtectionPhase::Armed),
        "disarmed" => Ok(PlacementProtectionPhase::Disarmed),
        _ => Err(PlacementError::ProtectionUnsafe),
    }
}

// Requires one owner-only private directory metadata record.
fn validate_private_directory(
    metadata: &fs::Metadata,
    owner_user_id: u32,
) -> Result<(), PlacementError> {
    if !metadata.file_type().is_dir()
        || metadata.uid() != owner_user_id
        || metadata.mode() & 0o077 != 0
    {
        return Err(PlacementError::ProtectionUnsafe);
    }
    Ok(())
}

// Requires one bounded owner-only private regular file metadata record.
fn validate_private_file_metadata(
    metadata: &fs::Metadata,
    owner_user_id: u32,
    maximum_bytes: usize,
) -> Result<(), PlacementError> {
    if !metadata.file_type().is_file()
        || metadata.uid() != owner_user_id
        || metadata.mode() & 0o077 != 0
        || metadata.len() > maximum_bytes as u64
    {
        return Err(PlacementError::ProtectionUnsafe);
    }
    Ok(())
}

// Syncs one directory after an atomic file or entry mutation.
fn sync_directory(path: &Path) -> Result<(), PlacementError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| PlacementError::ProtectionUnsafe)
}
