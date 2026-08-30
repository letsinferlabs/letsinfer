// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::Arc;

use li_core_interface::InstallationId;

use crate::{
    WatchdogConfiguration, WatchdogError, WatchdogProtocolCapabilities, WatchdogProtocolDataError,
    WatchdogProtocolIdentityProvider, WatchdogProtocolResidentStatus, WatchdogProtocolSiteStatus,
};

pub const WATCHDOG_PUBLIC_STATE_MAX_BYTES: usize = 2_047;

const WATCHDOG_PUBLIC_STATE_FIELD_COUNT: usize = 13;
const WATCHDOG_PUBLIC_STATE_MAX_TEXT_BYTES: usize = 127;

// Captures one stable public-state descriptor read without exposing native I/O.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogPublicStateFile {
    bytes: Vec<u8>,
    owner_user_id: u32,
    mode: u32,
    link_count: u64,
    is_regular_file: bool,
    is_stable: bool,
}

impl WatchdogPublicStateFile {
    // Creates one exact system or deterministic mock file observation.
    pub fn new(
        bytes: Vec<u8>,
        owner_user_id: u32,
        mode: u32,
        link_count: u64,
        is_regular_file: bool,
        is_stable: bool,
    ) -> Self {
        Self {
            bytes,
            owner_user_id,
            mode,
            link_count,
            is_regular_file,
            is_stable,
        }
    }
}

// Reads one required bounded public-state snapshot through an isolated native boundary.
pub trait WatchdogPublicStateFileProvider: Send + Sync {
    // Returns descriptor metadata and bytes without applying product identity policy.
    fn read(
        &self,
        path: &Path,
        maximum_bytes: usize,
    ) -> Result<WatchdogPublicStateFile, WatchdogError>;
}

// Carries the exact live status fields that the C safety supervisor derives at request time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogProtocolRuntimeStatus {
    service_state: String,
    engine_state: String,
    protection_phase: String,
    protection_armed: bool,
    trip_latched: bool,
    container_name: String,
}

impl WatchdogProtocolRuntimeStatus {
    // Creates one complete live projection without supplying lifecycle defaults.
    pub fn new(
        service_state: String,
        engine_state: String,
        protection_phase: String,
        protection_armed: bool,
        trip_latched: bool,
        container_name: String,
    ) -> Self {
        Self {
            service_state,
            engine_state,
            protection_phase,
            protection_armed,
            trip_latched,
            container_name,
        }
    }
}

// Supplies live engine and protection state from the resident safety owner.
pub trait WatchdogProtocolRuntimeStatusProvider: Send + Sync {
    // Returns every live protocol field from one coherent safety snapshot.
    fn status(&self) -> Result<WatchdogProtocolRuntimeStatus, WatchdogError>;
}

// Owns configuration capabilities and the established public-state read contract.
pub struct FilesystemWatchdogProtocolIdentityProvider {
    configuration: WatchdogConfiguration,
    owner_user_id: u32,
    physical_gpu_count: u32,
    files: Arc<dyn WatchdogPublicStateFileProvider>,
    runtime: Arc<dyn WatchdogProtocolRuntimeStatusProvider>,
}

impl FilesystemWatchdogProtocolIdentityProvider {
    // Creates one identity provider from exact loaded configuration and initialized hardware.
    pub fn new(
        configuration: WatchdogConfiguration,
        owner_user_id: u32,
        physical_gpu_count: u32,
        files: Arc<dyn WatchdogPublicStateFileProvider>,
        runtime: Arc<dyn WatchdogProtocolRuntimeStatusProvider>,
    ) -> Self {
        Self {
            configuration,
            owner_user_id,
            physical_gpu_count,
            files,
            runtime,
        }
    }

    // Returns the legacy single-target public state for direct provider validation.
    pub fn site_status(&self) -> Result<WatchdogProtocolSiteStatus, WatchdogProtocolDataError> {
        self.current_site_status()
            .map_err(|_| WatchdogProtocolDataError::Unavailable)
    }

    // Reads and combines one stable public descriptor with one coherent live status snapshot.
    fn current_site_status(&self) -> Result<WatchdogProtocolSiteStatus, WatchdogError> {
        let file = self.files.read(
            self.configuration.site_state_path(),
            WATCHDOG_PUBLIC_STATE_MAX_BYTES,
        )?;
        validate_public_state_file(&file, self.owner_user_id)?;
        let public_state = parse_public_state(&file.bytes)?;
        if public_state.installation_id != self.configuration.installation_id() {
            return Err(public_state_error(
                "public state installation identity is stale",
            ));
        }
        let runtime = self.runtime.status()?;
        WatchdogProtocolSiteStatus::new(
            public_state.release,
            public_state.model,
            public_state.engine,
            public_state.runtime_name,
            public_state.runtime_version,
            public_state.manifest_sha256,
            public_state.cache_provider,
            public_state.cache_persistent,
            public_state.inference_port,
            public_state.maximum_connections,
            public_state.maximum_active_requests,
            public_state.maximum_context_tokens,
            runtime.service_state,
            runtime.engine_state,
            runtime.protection_phase,
            runtime.protection_armed,
            runtime.trip_latched,
            runtime.container_name,
            public_state.installation_id,
        )
    }
}

impl WatchdogProtocolIdentityProvider for FilesystemWatchdogProtocolIdentityProvider {
    // Returns capabilities from the exact resident configuration and initialized GPU set.
    fn capabilities(&self) -> Result<WatchdogProtocolCapabilities, WatchdogProtocolDataError> {
        WatchdogProtocolCapabilities::new(
            self.configuration.sample_interval_milliseconds(),
            self.configuration.flush_interval_milliseconds(),
            self.physical_gpu_count,
        )
        .map_err(|_| WatchdogProtocolDataError::Unavailable)
    }

    // Returns the complete public and live status or one closed unavailable result.
    fn site_status(
        &self,
        _binding: &crate::WatchdogControllerBinding,
    ) -> Result<WatchdogProtocolSiteStatus, WatchdogProtocolDataError> {
        self.current_site_status()
            .map_err(|_| WatchdogProtocolDataError::Unavailable)
    }

    // Returns resident readiness from immutable configuration without requiring a placement.
    fn resident_status(&self) -> Result<WatchdogProtocolResidentStatus, WatchdogProtocolDataError> {
        WatchdogProtocolResidentStatus::ready(
            self.configuration.node_id().clone(),
            self.configuration.core_release().to_string(),
            self.configuration.core_source_identity().clone(),
            InstallationId::parse(self.configuration.installation_id())
                .map_err(|_| WatchdogProtocolDataError::Unavailable)?,
        )
        .map_err(|_| WatchdogProtocolDataError::Unavailable)
    }
}

// Reads public state through one owner-bound no-follow descriptor and proves path stability.
pub struct SystemWatchdogPublicStateFileProvider;

impl WatchdogPublicStateFileProvider for SystemWatchdogPublicStateFileProvider {
    // Rejects links, substitution, truncation, growth, and every read outside the fixed bound.
    fn read(
        &self,
        path: &Path,
        maximum_bytes: usize,
    ) -> Result<WatchdogPublicStateFile, WatchdogError> {
        if maximum_bytes == 0 || maximum_bytes > WATCHDOG_PUBLIC_STATE_MAX_BYTES {
            return Err(public_state_provider_error(
                "public state read bound is invalid",
            ));
        }
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| public_state_provider_error("public state could not be opened"))?;
        let initial = file
            .metadata()
            .map_err(|_| public_state_provider_error("public state metadata is unavailable"))?;
        if initial.len() == 0 || initial.len() > maximum_bytes as u64 {
            return Err(public_state_provider_error("public state size is invalid"));
        }
        let mut bytes = Vec::with_capacity(initial.len() as usize);
        file.by_ref()
            .take(maximum_bytes as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| public_state_provider_error("public state could not be read"))?;
        let final_descriptor = file
            .metadata()
            .map_err(|_| public_state_provider_error("public state metadata is unavailable"))?;
        let final_path = std::fs::symlink_metadata(path)
            .map_err(|_| public_state_provider_error("public state path was replaced"))?;
        let stable = stable_file_identity(&initial, &final_descriptor)
            && stable_file_identity(&initial, &final_path)
            && bytes.len() as u64 == initial.len();
        Ok(WatchdogPublicStateFile::new(
            bytes,
            initial.uid(),
            initial.mode() & 0o777,
            initial.nlink(),
            initial.file_type().is_file(),
            stable,
        ))
    }
}

// Stores every field from the established version-one C public-state descriptor.
struct WatchdogPublicState {
    installation_id: String,
    release: String,
    model: String,
    engine: String,
    runtime_name: String,
    runtime_version: String,
    manifest_sha256: String,
    cache_provider: String,
    cache_persistent: bool,
    inference_port: u32,
    maximum_connections: u32,
    maximum_active_requests: u32,
    maximum_context_tokens: u32,
}

// Requires an owner-private stable single-link regular file under the unchanged C bound.
fn validate_public_state_file(
    file: &WatchdogPublicStateFile,
    owner_user_id: u32,
) -> Result<(), WatchdogError> {
    if file.bytes.is_empty()
        || file.bytes.len() > WATCHDOG_PUBLIC_STATE_MAX_BYTES
        || file.owner_user_id != owner_user_id
        || file.mode & 0o077 != 0
        || file.link_count != 1
        || !file.is_regular_file
        || !file.is_stable
    {
        return Err(public_state_error("public state file identity is unsafe"));
    }
    Ok(())
}

// Parses the exact version-one C field set and rejects unknown, duplicate, or missing fields.
fn parse_public_state(source: &[u8]) -> Result<WatchdogPublicState, WatchdogError> {
    if source.is_empty()
        || source.len() > WATCHDOG_PUBLIC_STATE_MAX_BYTES
        || source.last() != Some(&b'\n')
        || source.contains(&0)
        || source.contains(&b'\r')
    {
        return Err(public_state_error("public state framing is invalid"));
    }
    let source = std::str::from_utf8(source)
        .map_err(|_| public_state_error("public state text is invalid"))?;
    let mut version = None;
    let mut fields = BTreeMap::new();
    for line in source
        .strip_suffix('\n')
        .expect("checked newline")
        .split('\n')
    {
        let (name, value) = line
            .split_once('=')
            .filter(|(name, value)| !name.is_empty() && !value.is_empty() && !value.contains('='))
            .ok_or_else(|| public_state_error("public state field is malformed"))?;
        if name == "version" {
            if version.replace(value).is_some() {
                return Err(public_state_error("public state version is duplicated"));
            }
        } else if fields.insert(name, value).is_some() {
            return Err(public_state_error("public state field is duplicated"));
        }
    }
    let expected = [
        "cache_persistent",
        "cache_provider",
        "engine",
        "inference_port",
        "installation_id",
        "manifest_sha256",
        "max_active_requests",
        "max_connections",
        "max_context_tokens",
        "model",
        "release",
        "runtime_name",
        "runtime_version",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    if version != Some("1")
        || fields.len() != WATCHDOG_PUBLIC_STATE_FIELD_COUNT
        || fields.keys().copied().collect::<BTreeSet<_>>() != expected
    {
        return Err(public_state_error(
            "public state schema identity is unsupported",
        ));
    }
    let installation_id = lowercase_sha256(fields["installation_id"])?;
    let manifest_sha256 = lowercase_sha256(fields["manifest_sha256"])?;
    let cache_persistent = match fields["cache_persistent"] {
        "true" => true,
        "false" => false,
        _ => return Err(public_state_error("public state boolean is invalid")),
    };
    let inference_port = positive_u32(fields["inference_port"])?;
    if inference_port > u32::from(u16::MAX) {
        return Err(public_state_error("public state inference port is invalid"));
    }
    Ok(WatchdogPublicState {
        installation_id,
        release: status_text(fields["release"])?,
        model: status_text(fields["model"])?,
        engine: status_text(fields["engine"])?,
        runtime_name: status_text(fields["runtime_name"])?,
        runtime_version: status_text(fields["runtime_version"])?,
        manifest_sha256,
        cache_provider: status_text(fields["cache_provider"])?,
        cache_persistent,
        inference_port,
        maximum_connections: positive_u32(fields["max_connections"])?,
        maximum_active_requests: positive_u32(fields["max_active_requests"])?,
        maximum_context_tokens: positive_u32(fields["max_context_tokens"])?,
    })
}

// Converts one required positive decimal field without signs, spaces, or overflow.
fn positive_u32(value: &str) -> Result<u32, WatchdogError> {
    if !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(public_state_error("public state number is invalid"));
    }
    let value = value
        .parse::<u32>()
        .map_err(|_| public_state_error("public state number is out of range"))?;
    if value == 0 {
        return Err(public_state_error("public state number is invalid"));
    }
    Ok(value)
}

// Copies one nonempty C-compatible status token under the fixed visible bound.
fn status_text(value: &str) -> Result<String, WatchdogError> {
    if value.is_empty()
        || value.len() > WATCHDOG_PUBLIC_STATE_MAX_TEXT_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'_' | b':' | b'/' | b'@' | b'+' | b'-')
        })
    {
        return Err(public_state_error("public state status text is invalid"));
    }
    Ok(value.to_string())
}

// Copies one exact lowercase SHA-256 identity.
fn lowercase_sha256(value: &str) -> Result<String, WatchdogError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(public_state_error("public state digest is invalid"));
    }
    Ok(value.to_string())
}

// Compares descriptor and path identities before accepting one coherent snapshot.
fn stable_file_identity(initial: &std::fs::Metadata, final_metadata: &std::fs::Metadata) -> bool {
    initial.dev() == final_metadata.dev()
        && initial.ino() == final_metadata.ino()
        && initial.uid() == final_metadata.uid()
        && initial.mode() == final_metadata.mode()
        && initial.nlink() == final_metadata.nlink()
        && initial.len() == final_metadata.len()
        && initial.mtime() == final_metadata.mtime()
        && initial.mtime_nsec() == final_metadata.mtime_nsec()
        && initial.ctime() == final_metadata.ctime()
        && initial.ctime_nsec() == final_metadata.ctime_nsec()
}

// Creates one stable redacted public-state contract failure.
const fn public_state_error(reason: &'static str) -> WatchdogError {
    WatchdogError::InvalidContract { reason }
}

// Creates one stable redacted native public-state failure.
const fn public_state_provider_error(reason: &'static str) -> WatchdogError {
    WatchdogError::provider("public state", reason)
}
