// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::{
    WatchdogError, WatchdogLinuxCapability, WatchdogSampleTelemetry,
    WATCHDOG_SAMPLE_GATEWAY_AVAILABLE,
};

const WATCHDOG_GATEWAY_TELEMETRY_MAX_BYTES: usize = 4_096;
const WATCHDOG_GATEWAY_TELEMETRY_MAX_AGE_MILLISECONDS: u64 = 5_000;
const WATCHDOG_GATEWAY_TELEMETRY_FUTURE_TOLERANCE_MILLISECONDS: u64 = 1_000;
const WATCHDOG_GATEWAY_TELEMETRY_FIELDS: usize = 19;

// Stores the exact complete gateway telemetry-v2 counter projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogGatewayTelemetry {
    active_requests: u32,
    connected_clients: u32,
    queued_requests: u32,
    counters: [u64; 16],
}

impl WatchdogGatewayTelemetry {
    // Applies one complete fresh counter record and only then marks it available.
    pub fn apply(&self, telemetry: &mut WatchdogSampleTelemetry) {
        telemetry.active_requests = self.active_requests;
        telemetry.connected_clients = self.connected_clients;
        telemetry.queued_requests = self.queued_requests;
        telemetry.requests_received = self.counters[0];
        telemetry.requests_admitted = self.counters[1];
        telemetry.requests_completed = self.counters[2];
        telemetry.requests_failed = self.counters[3];
        telemetry.requests_cancelled = self.counters[4];
        telemetry.requests_retried = self.counters[5];
        telemetry.input_tokens = self.counters[6];
        telemetry.output_tokens = self.counters[7];
        telemetry.cached_tokens = self.counters[8];
        telemetry.queue_milliseconds = self.counters[9];
        telemetry.ttft_milliseconds = self.counters[10];
        telemetry.decode_milliseconds = self.counters[11];
        telemetry.exact_token_requests = self.counters[12];
        telemetry.prefix_cache_hits = self.counters[13];
        telemetry.usage_records_dropped = self.counters[14];
        telemetry.usage_write_errors = self.counters[15];
        telemetry.flags |= WATCHDOG_SAMPLE_GATEWAY_AVAILABLE;
    }

    // Returns whether every monotonic counter is at least the previous value.
    fn follows(&self, previous: &Self) -> bool {
        self.counters
            .iter()
            .zip(previous.counters.iter())
            .all(|(current, previous)| current >= previous)
    }
}

// Captures one stable gateway file read without giving the reader native I/O ownership.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogGatewayTelemetryFile {
    bytes: Vec<u8>,
    owner_user_id: u32,
    mode: u32,
    link_count: u64,
    is_regular_file: bool,
    is_stable: bool,
    device_id: u64,
    inode: u64,
    modified_unix_milliseconds: u64,
}

impl WatchdogGatewayTelemetryFile {
    // Creates one exact system or mock file observation.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        bytes: Vec<u8>,
        owner_user_id: u32,
        mode: u32,
        link_count: u64,
        is_regular_file: bool,
        is_stable: bool,
        device_id: u64,
        inode: u64,
        modified_unix_milliseconds: u64,
    ) -> Self {
        Self {
            bytes,
            owner_user_id,
            mode,
            link_count,
            is_regular_file,
            is_stable,
            device_id,
            inode,
            modified_unix_milliseconds,
        }
    }
}

// Reads one optional owner-only gateway telemetry snapshot.
pub trait WatchdogGatewayTelemetryFileProvider: Send + Sync {
    // Returns absence explicitly or one bounded descriptor-stable observation.
    fn read(
        &self,
        path: &Path,
        maximum_bytes: usize,
    ) -> Result<WatchdogLinuxCapability<WatchdogGatewayTelemetryFile>, WatchdogError>;
}

// Supplies one optional complete gateway snapshot to the Linux sampler.
pub trait WatchdogGatewayTelemetrySampleProvider: Send + Sync {
    // Samples the exact configured gateway source at one wall-clock instant.
    fn sample(
        &self,
        now_unix_milliseconds: u64,
    ) -> Result<WatchdogLinuxCapability<WatchdogGatewayTelemetry>, WatchdogError>;
}

// Preserves explicit unavailability when no gateway reader is composed.
pub struct UnsupportedWatchdogGatewayTelemetryProvider;

impl WatchdogGatewayTelemetrySampleProvider for UnsupportedWatchdogGatewayTelemetryProvider {
    // Returns unsupported without fabricating a complete zero counter record.
    fn sample(
        &self,
        _now_unix_milliseconds: u64,
    ) -> Result<WatchdogLinuxCapability<WatchdogGatewayTelemetry>, WatchdogError> {
        Ok(WatchdogLinuxCapability::Unsupported)
    }
}

// Owns telemetry-v2 parsing, freshness, sequence, and restart judgment.
pub struct WatchdogGatewayTelemetryProvider {
    path: PathBuf,
    owner_user_id: u32,
    files: Box<dyn WatchdogGatewayTelemetryFileProvider>,
    state: Mutex<Option<WatchdogGatewayTelemetryState>>,
}

impl WatchdogGatewayTelemetryProvider {
    // Creates one reader over an explicit normalized configuration path.
    pub fn new(
        path: PathBuf,
        owner_user_id: u32,
        files: Box<dyn WatchdogGatewayTelemetryFileProvider>,
    ) -> Result<Self, WatchdogError> {
        if !path.is_absolute() {
            return Err(gateway_error("gateway telemetry path is invalid"));
        }
        Ok(Self {
            path,
            owner_user_id,
            files,
            state: Mutex::new(None),
        })
    }

    // Reads one complete fresh snapshot while treating absence and staleness as unsupported.
    pub fn sample(
        &self,
        now_unix_milliseconds: u64,
    ) -> Result<WatchdogLinuxCapability<WatchdogGatewayTelemetry>, WatchdogError> {
        if now_unix_milliseconds == 0 {
            return Err(gateway_error("gateway telemetry clock is invalid"));
        }
        let file = match self
            .files
            .read(&self.path, WATCHDOG_GATEWAY_TELEMETRY_MAX_BYTES)?
        {
            WatchdogLinuxCapability::Available(file) => file,
            WatchdogLinuxCapability::Unsupported => {
                return Ok(WatchdogLinuxCapability::Unsupported)
            }
        };
        validate_gateway_file(&file, self.owner_user_id)?;
        if file.modified_unix_milliseconds
            > now_unix_milliseconds
                .saturating_add(WATCHDOG_GATEWAY_TELEMETRY_FUTURE_TOLERANCE_MILLISECONDS)
            || now_unix_milliseconds.saturating_sub(file.modified_unix_milliseconds)
                > WATCHDOG_GATEWAY_TELEMETRY_MAX_AGE_MILLISECONDS
        {
            return Ok(WatchdogLinuxCapability::Unsupported);
        }
        let telemetry = parse_gateway_telemetry(&file.bytes)?;
        let identity = (file.device_id, file.inode);
        let mut state = self
            .state
            .lock()
            .map_err(|_| WatchdogError::StateUnavailable)?;
        if let Some(previous) = state.as_ref() {
            if identity == previous.identity {
                if file.modified_unix_milliseconds < previous.modified_unix_milliseconds
                    || (file.modified_unix_milliseconds == previous.modified_unix_milliseconds
                        && telemetry != previous.telemetry)
                    || !telemetry.follows(&previous.telemetry)
                {
                    return Err(gateway_error("gateway telemetry sequence regressed"));
                }
            }
        }
        *state = Some(WatchdogGatewayTelemetryState {
            identity,
            modified_unix_milliseconds: file.modified_unix_milliseconds,
            telemetry: telemetry.clone(),
        });
        Ok(WatchdogLinuxCapability::Available(telemetry))
    }
}

impl WatchdogGatewayTelemetrySampleProvider for WatchdogGatewayTelemetryProvider {
    // Delegates through the stateful freshness and restart judgment boundary.
    fn sample(
        &self,
        now_unix_milliseconds: u64,
    ) -> Result<WatchdogLinuxCapability<WatchdogGatewayTelemetry>, WatchdogError> {
        WatchdogGatewayTelemetryProvider::sample(self, now_unix_milliseconds)
    }
}

// Retains only the exact prior file identity and monotonic counters.
struct WatchdogGatewayTelemetryState {
    identity: (u64, u64),
    modified_unix_milliseconds: u64,
    telemetry: WatchdogGatewayTelemetry,
}

// Reads gateway telemetry through one stable owner-only no-follow descriptor.
pub struct SystemWatchdogGatewayTelemetryFileProvider;

impl WatchdogGatewayTelemetryFileProvider for SystemWatchdogGatewayTelemetryFileProvider {
    // Reads one existing bounded file and returns absence without inventing values.
    fn read(
        &self,
        path: &Path,
        maximum_bytes: usize,
    ) -> Result<WatchdogLinuxCapability<WatchdogGatewayTelemetryFile>, WatchdogError> {
        let mut file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(WatchdogLinuxCapability::Unsupported)
            }
            Err(_) => {
                return Err(gateway_provider_error(
                    "gateway telemetry could not be opened",
                ))
            }
        };
        let initial = file
            .metadata()
            .map_err(|_| gateway_provider_error("gateway telemetry metadata is unavailable"))?;
        if initial.len() == 0 || initial.len() > maximum_bytes as u64 {
            return Err(gateway_provider_error("gateway telemetry size is invalid"));
        }
        let mut bytes = Vec::with_capacity(initial.len() as usize);
        file.by_ref()
            .take(maximum_bytes as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| gateway_provider_error("gateway telemetry could not be read"))?;
        let final_metadata = file
            .metadata()
            .map_err(|_| gateway_provider_error("gateway telemetry metadata is unavailable"))?;
        let modified = modified_milliseconds(&initial)?;
        Ok(WatchdogLinuxCapability::Available(
            WatchdogGatewayTelemetryFile::new(
                bytes,
                initial.uid(),
                initial.mode() & 0o777,
                initial.nlink(),
                initial.file_type().is_file(),
                stable_metadata(&initial, &final_metadata),
                initial.dev(),
                initial.ino(),
                modified,
            ),
        ))
    }
}

// Requires the exact C telemetry-v2 descriptor and bounded read contract.
fn validate_gateway_file(
    file: &WatchdogGatewayTelemetryFile,
    owner_user_id: u32,
) -> Result<(), WatchdogError> {
    if file.bytes.is_empty()
        || file.bytes.len() > WATCHDOG_GATEWAY_TELEMETRY_MAX_BYTES
        || file.owner_user_id != owner_user_id
        || file.mode & 0o077 != 0
        || file.link_count != 1
        || !file.is_regular_file
        || !file.is_stable
        || file.device_id == 0
        || file.inode == 0
        || file.modified_unix_milliseconds == 0
    {
        return Err(gateway_error("gateway telemetry file identity is unsafe"));
    }
    Ok(())
}

// Parses the unchanged version-two C field vocabulary and exact cardinality.
fn parse_gateway_telemetry(source: &[u8]) -> Result<WatchdogGatewayTelemetry, WatchdogError> {
    let source = std::str::from_utf8(source)
        .map_err(|_| gateway_error("gateway telemetry text is invalid"))?;
    if source.contains('\0') {
        return Err(gateway_error("gateway telemetry framing is invalid"));
    }
    let mut version = false;
    let mut fields = BTreeMap::new();
    for line in source.lines() {
        let (name, value) = line
            .split_once('=')
            .filter(|(_, value)| !value.is_empty() && !value.contains('='))
            .ok_or_else(|| gateway_error("gateway telemetry field is malformed"))?;
        if name == "version" {
            if version || value != "2" {
                return Err(gateway_error("gateway telemetry version is invalid"));
            }
            version = true;
            continue;
        }
        if fields.insert(name, value).is_some() {
            return Err(gateway_error("gateway telemetry field is duplicated"));
        }
    }
    let u32_value = |name| -> Result<u32, WatchdogError> {
        numeric_field(&fields, name)?
            .try_into()
            .map_err(|_| gateway_error("gateway telemetry value is out of range"))
    };
    let names = [
        "requests_received",
        "requests_admitted",
        "requests_completed",
        "requests_failed",
        "requests_cancelled",
        "requests_retried",
        "input_tokens",
        "output_tokens",
        "cached_tokens",
        "queue_milliseconds",
        "ttft_milliseconds",
        "decode_milliseconds",
        "exact_token_requests",
        "prefix_cache_hits",
        "usage_records_dropped",
        "usage_write_errors",
    ];
    if !version || fields.len() != WATCHDOG_GATEWAY_TELEMETRY_FIELDS {
        return Err(gateway_error("gateway telemetry record is incomplete"));
    }
    let mut counters = [0_u64; 16];
    for (index, name) in names.iter().enumerate() {
        counters[index] = numeric_field(&fields, name)?;
    }
    Ok(WatchdogGatewayTelemetry {
        active_requests: u32_value("active_requests")?,
        connected_clients: u32_value("connected_clients")?,
        queued_requests: u32_value("queued_requests")?,
        counters,
    })
}

// Parses one exact unsigned decimal field without signs or whitespace.
fn numeric_field(fields: &BTreeMap<&str, &str>, name: &str) -> Result<u64, WatchdogError> {
    let value = fields
        .get(name)
        .ok_or_else(|| gateway_error("gateway telemetry field is missing"))?;
    if !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(gateway_error("gateway telemetry value is invalid"));
    }
    value
        .parse()
        .map_err(|_| gateway_error("gateway telemetry value is out of range"))
}

// Converts one nonnegative native modification timestamp to milliseconds.
fn modified_milliseconds(metadata: &std::fs::Metadata) -> Result<u64, WatchdogError> {
    let seconds = u64::try_from(metadata.mtime())
        .map_err(|_| gateway_provider_error("gateway telemetry timestamp is invalid"))?;
    let nanoseconds = u64::try_from(metadata.mtime_nsec())
        .map_err(|_| gateway_provider_error("gateway telemetry timestamp is invalid"))?;
    seconds
        .checked_mul(1_000)
        .and_then(|value| value.checked_add(nanoseconds / 1_000_000))
        .ok_or_else(|| gateway_provider_error("gateway telemetry timestamp is invalid"))
}

// Compares the complete file identity before and after a bounded read.
fn stable_metadata(initial: &std::fs::Metadata, final_metadata: &std::fs::Metadata) -> bool {
    initial.dev() == final_metadata.dev()
        && initial.ino() == final_metadata.ino()
        && initial.uid() == final_metadata.uid()
        && initial.mode() == final_metadata.mode()
        && initial.nlink() == final_metadata.nlink()
        && initial.len() == final_metadata.len()
        && initial.mtime() == final_metadata.mtime()
        && initial.mtime_nsec() == final_metadata.mtime_nsec()
}

// Creates one redacted gateway telemetry contract failure.
const fn gateway_error(reason: &'static str) -> WatchdogError {
    WatchdogError::InvalidContract { reason }
}

// Creates one redacted gateway telemetry native-provider failure.
const fn gateway_provider_error(reason: &'static str) -> WatchdogError {
    WatchdogError::provider("gateway telemetry", reason)
}
