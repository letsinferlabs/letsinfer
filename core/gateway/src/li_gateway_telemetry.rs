// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};

use getrandom::fill;
use li_core_interface::{LogicalModelName, NodeId, PlacementGroupId, UnixMilliseconds};

use crate::{GatewayError, GatewayRoute};

const TELEMETRY_SCHEMA_VERSION: u32 = 2;
const MAX_PLACEMENT_GROUP_ACTIVITY: usize = 4_096;
const MAX_PLACEMENT_GROUP_SAMPLES: usize = 16_384;
const PLACEMENT_GROUP_RATE_WINDOW_MILLISECONDS: u64 = 5_000;
const TELEMETRY_STALE_MILLISECONDS: u64 = 3_500;
const TELEMETRY_V2_MAX_BYTES: usize = 4_096;
const TELEMETRY_TEMPORARY_IDENTITY_BYTES: usize = 16;

// Carries the manager-owned aggregate counters published by telemetry schema 2.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GatewayTelemetryCounters {
    requests_received: u64,
    requests_admitted: u64,
    requests_completed: u64,
    requests_failed: u64,
    requests_cancelled: u64,
    requests_retried: u64,
    active_requests: u64,
    queued_requests: u64,
    input_tokens: u64,
    output_tokens: u64,
    cached_tokens: u64,
    queue_milliseconds: u64,
    ttft_milliseconds: u64,
    decode_milliseconds: u64,
    exact_token_requests: u64,
    prefix_cache_hits: u64,
}

impl GatewayTelemetryCounters {
    // Returns all requests presented to a public or private admission entry point.
    pub const fn requests_received(&self) -> u64 {
        self.requests_received
    }

    // Returns requests that acquired their first placement-group reservation.
    pub const fn requests_admitted(&self) -> u64 {
        self.requests_admitted
    }

    // Returns requests that completed with coherent exact Engine usage.
    pub const fn requests_completed(&self) -> u64 {
        self.requests_completed
    }

    // Returns requests that reached one terminal non-cancellation failure.
    pub const fn requests_failed(&self) -> u64 {
        self.requests_failed
    }

    // Returns requests explicitly cancelled by a caller or disconnected client.
    pub const fn requests_cancelled(&self) -> u64 {
        self.requests_cancelled
    }

    // Returns successful pre-output moves away from a failed placement group.
    pub const fn requests_retried(&self) -> u64 {
        self.requests_retried
    }

    // Returns the current active reservation gauge.
    pub const fn active_requests(&self) -> u64 {
        self.active_requests
    }

    // Returns the current bounded FIFO queue gauge.
    pub const fn queued_requests(&self) -> u64 {
        self.queued_requests
    }

    // Returns exact prompt tokens observed on completed requests.
    pub const fn input_tokens(&self) -> u64 {
        self.input_tokens
    }

    // Returns exact generated tokens observed on completed requests.
    pub const fn output_tokens(&self) -> u64 {
        self.output_tokens
    }

    // Returns exact prompt tokens restored from compatible cache state.
    pub const fn cached_tokens(&self) -> u64 {
        self.cached_tokens
    }

    // Returns accumulated time spent waiting for placement capacity.
    pub const fn queue_milliseconds(&self) -> u64 {
        self.queue_milliseconds
    }

    // Returns accumulated dispatch-to-first-response-byte duration.
    pub const fn ttft_milliseconds(&self) -> u64 {
        self.ttft_milliseconds
    }

    // Returns accumulated first-response-byte-to-completion duration.
    pub const fn decode_milliseconds(&self) -> u64 {
        self.decode_milliseconds
    }

    // Returns completed requests carrying exact Engine token accounting.
    pub const fn exact_token_requests(&self) -> u64 {
        self.exact_token_requests
    }

    // Returns exact-token requests with a positive cached-token observation.
    pub const fn prefix_cache_hits(&self) -> u64 {
        self.prefix_cache_hits
    }
}

// Carries bounded cumulative activity for one atomic placement group.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GatewayPlacementGroupCounters {
    requests_admitted: u64,
    requests_completed: u64,
    requests_failed: u64,
    requests_cancelled: u64,
    requests_retried: u64,
    input_tokens: u64,
    output_tokens: u64,
    cached_tokens: u64,
}

impl GatewayPlacementGroupCounters {
    // Returns requests first admitted to this placement group.
    pub const fn requests_admitted(&self) -> u64 {
        self.requests_admitted
    }

    // Returns requests completed by this placement group.
    pub const fn requests_completed(&self) -> u64 {
        self.requests_completed
    }

    // Returns requests that failed while owned by this placement group.
    pub const fn requests_failed(&self) -> u64 {
        self.requests_failed
    }

    // Returns requests cancelled while owned by this placement group.
    pub const fn requests_cancelled(&self) -> u64 {
        self.requests_cancelled
    }

    // Returns requests moved away from this group before output began.
    pub const fn requests_retried(&self) -> u64 {
        self.requests_retried
    }

    // Returns exact prompt tokens completed by this placement group.
    pub const fn input_tokens(&self) -> u64 {
        self.input_tokens
    }

    // Returns exact generated tokens completed by this placement group.
    pub const fn output_tokens(&self) -> u64 {
        self.output_tokens
    }

    // Returns exact cached prompt tokens completed by this placement group.
    pub const fn cached_tokens(&self) -> u64 {
        self.cached_tokens
    }
}

// Carries recent exact-token rates without retaining individual request history.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct GatewayPlacementGroupRates {
    input_tokens_per_second: f64,
    output_tokens_per_second: f64,
    cached_tokens_per_second: f64,
}

impl GatewayPlacementGroupRates {
    // Returns recent exact prompt-token throughput.
    pub const fn input_tokens_per_second(self) -> f64 {
        self.input_tokens_per_second
    }

    // Returns recent exact generated-token throughput.
    pub const fn output_tokens_per_second(self) -> f64 {
        self.output_tokens_per_second
    }

    // Returns recent exact cached-token throughput.
    pub const fn cached_tokens_per_second(self) -> f64 {
        self.cached_tokens_per_second
    }
}

// Carries the current queue gauge for one logical model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayModelActivity {
    model: LogicalModelName,
    queued_requests: u64,
}

impl GatewayModelActivity {
    // Returns the exact logical model represented by this activity row.
    pub const fn model(&self) -> &LogicalModelName {
        &self.model
    }

    // Returns the current number of queued requests for this model.
    pub const fn queued_requests(&self) -> u64 {
        self.queued_requests
    }
}

// Carries one bounded placement-group row in the schema-2 activity snapshot.
#[derive(Clone, Debug, PartialEq)]
pub struct GatewayPlacementGroupActivity {
    placement_group_id: PlacementGroupId,
    model: LogicalModelName,
    endpoint_node_id: NodeId,
    active_requests: u64,
    max_active_requests: u64,
    counters: GatewayPlacementGroupCounters,
    rates: GatewayPlacementGroupRates,
}

impl GatewayPlacementGroupActivity {
    // Returns the atomic placement-group identity.
    pub const fn placement_group_id(&self) -> &PlacementGroupId {
        &self.placement_group_id
    }

    // Returns the logical model served by this placement group.
    pub const fn model(&self) -> &LogicalModelName {
        &self.model
    }

    // Returns the node that owns the placement-group endpoint.
    pub const fn endpoint_node_id(&self) -> &NodeId {
        &self.endpoint_node_id
    }

    // Returns the current active reservation gauge for this group.
    pub const fn active_requests(&self) -> u64 {
        self.active_requests
    }

    // Returns the latest declared concurrent capacity for this group.
    pub const fn max_active_requests(&self) -> u64 {
        self.max_active_requests
    }

    // Returns bounded cumulative group counters.
    pub const fn counters(&self) -> &GatewayPlacementGroupCounters {
        &self.counters
    }

    // Returns exact-token rates over the bounded five-second activity window.
    pub const fn rates(&self) -> GatewayPlacementGroupRates {
        self.rates
    }
}

// Carries one immutable secret-free schema-2 Gateway telemetry observation.
#[derive(Clone, Debug, PartialEq)]
pub struct GatewayTelemetrySnapshot {
    observed_at: UnixMilliseconds,
    counters: GatewayTelemetryCounters,
    models: Vec<GatewayModelActivity>,
    placement_groups: Vec<GatewayPlacementGroupActivity>,
}

impl GatewayTelemetrySnapshot {
    // Returns the stable Python-compatible telemetry schema version.
    pub const fn schema_version(&self) -> u32 {
        TELEMETRY_SCHEMA_VERSION
    }

    // Returns the maximum number of retained placement-group identities.
    pub const fn maximum_placement_group_activity() -> usize {
        MAX_PLACEMENT_GROUP_ACTIVITY
    }

    // Returns when this immutable snapshot was assembled.
    pub const fn observed_at(&self) -> UnixMilliseconds {
        self.observed_at
    }

    // Returns aggregate lifecycle, gauge, token, and duration counters.
    pub const fn counters(&self) -> &GatewayTelemetryCounters {
        &self.counters
    }

    // Returns sorted non-empty logical-model queue rows.
    pub fn models(&self) -> &[GatewayModelActivity] {
        &self.models
    }

    // Returns sorted bounded placement-group activity rows.
    pub fn placement_groups(&self) -> &[GatewayPlacementGroupActivity] {
        &self.placement_groups
    }
}

// Carries redacted publisher readiness without exposing paths or native errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GatewayTelemetryHealth {
    healthy: bool,
    last_success_at: Option<UnixMilliseconds>,
    last_failure_at: Option<UnixMilliseconds>,
}

impl GatewayTelemetryHealth {
    // Returns whether the latest publish succeeded and remains fresh.
    pub const fn is_healthy(self) -> bool {
        self.healthy
    }

    // Returns the most recent successful atomic publication time.
    pub const fn last_success_at(self) -> Option<UnixMilliseconds> {
        self.last_success_at
    }

    // Returns the most recent failed atomic publication time.
    pub const fn last_failure_at(self) -> Option<UnixMilliseconds> {
        self.last_failure_at
    }
}

// Atomically publishes one complete secret-free snapshot through native I/O.
pub trait GatewayTelemetryPublisher: Send + Sync {
    // Replaces the externally visible telemetry observation as one atomic operation.
    fn publish_atomically(&self, snapshot: &GatewayTelemetrySnapshot) -> Result<(), GatewayError>;
}

// Carries runtime counters that cannot be derived from one manager snapshot.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GatewayTelemetryRuntimeCounters {
    connected_clients: u32,
    usage_records_dropped: u64,
    usage_write_errors: u64,
}

impl GatewayTelemetryRuntimeCounters {
    // Creates one exact runtime-counter observation without assigning manager ownership.
    pub const fn new(
        connected_clients: u32,
        usage_records_dropped: u64,
        usage_write_errors: u64,
    ) -> Self {
        Self {
            connected_clients,
            usage_records_dropped,
            usage_write_errors,
        }
    }

    // Returns live accepted connections owned by the resident listener boundary.
    pub const fn connected_clients(self) -> u32 {
        self.connected_clients
    }

    // Returns usage records rejected by a bounded asynchronous writer, when one exists.
    pub const fn usage_records_dropped(self) -> u64 {
        self.usage_records_dropped
    }

    // Returns durable usage writes that failed after asynchronous acceptance, when one exists.
    pub const fn usage_write_errors(self) -> u64 {
        self.usage_write_errors
    }
}

// Supplies exact listener and usage-writer counters at publication time.
pub trait GatewayTelemetryRuntimeCounterProvider: Send + Sync {
    // Returns one complete runtime-counter observation without request or credential material.
    fn counters(&self) -> Result<GatewayTelemetryRuntimeCounters, GatewayError>;
}

// Supplies private random identities for same-directory temporary telemetry files.
trait GatewayTelemetryTemporaryIdentityProvider: Send + Sync {
    // Returns one canonical lowercase 128-bit identity.
    fn identity(&self) -> Result<String, GatewayError>;
}

// Uses the operating-system CSPRNG for production telemetry temporary identities.
struct SystemGatewayTelemetryTemporaryIdentityProvider;

impl GatewayTelemetryTemporaryIdentityProvider for SystemGatewayTelemetryTemporaryIdentityProvider {
    // Returns one random lowercase identity without exposing entropy failures.
    fn identity(&self) -> Result<String, GatewayError> {
        let mut bytes = [0_u8; TELEMETRY_TEMPORARY_IDENTITY_BYTES];
        fill(&mut bytes).map_err(|_| telemetry_file_error("temporary identity is unavailable"))?;
        Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
    }
}

// Defines one atomic owner-only telemetry replacement transaction.
trait GatewayTelemetryAtomicFileIo: Send + Sync {
    // Publishes one complete bounded payload through one same-directory temporary identity.
    fn replace(
        &self,
        path: &Path,
        payload: &[u8],
        owner_user_id: u32,
        temporary_identity: &str,
    ) -> Result<(), GatewayError>;
}

// Performs durable owner-only no-follow telemetry replacement on the native filesystem.
struct SystemGatewayTelemetryAtomicFileIo;

impl GatewayTelemetryAtomicFileIo for SystemGatewayTelemetryAtomicFileIo {
    // Validates destination identity, writes one private file, and atomically replaces it.
    fn replace(
        &self,
        path: &Path,
        payload: &[u8],
        owner_user_id: u32,
        temporary_identity: &str,
    ) -> Result<(), GatewayError> {
        validate_telemetry_path(path)?;
        if payload.is_empty()
            || payload.len() > TELEMETRY_V2_MAX_BYTES
            || !is_temporary_identity(temporary_identity)
        {
            return Err(telemetry_file_error("telemetry replacement is invalid"));
        }
        let parent = path
            .parent()
            .ok_or_else(|| telemetry_file_error("telemetry path is invalid"))?;
        validate_telemetry_directory(parent, owner_user_id)?;
        let previous = telemetry_file_identity(path, owner_user_id)?;
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| telemetry_file_error("telemetry path is invalid"))?;
        let temporary = parent.join(format!(".{file_name}.{temporary_identity}.tmp"));
        replace_telemetry_file(&temporary, path, payload, owner_user_id, previous)
    }
}

// Retains the stable descriptor identity observed before an atomic replacement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct GatewayTelemetryFileIdentity {
    device: u64,
    inode: u64,
}

// Stores the exact Watchdog telemetry-v2 field projection.
#[derive(Clone, Debug, Eq, PartialEq)]
struct GatewayTelemetryV2Record {
    active_requests: u32,
    connected_clients: u32,
    queued_requests: u32,
    counters: [u64; 16],
}

impl GatewayTelemetryV2Record {
    // Resolves one complete Watchdog projection from manager and runtime counter owners.
    fn from_snapshot(
        snapshot: &GatewayTelemetrySnapshot,
        runtime: GatewayTelemetryRuntimeCounters,
    ) -> Result<Self, GatewayError> {
        let counters = snapshot.counters();
        Ok(Self {
            active_requests: u32::try_from(counters.active_requests())
                .map_err(|_| telemetry_contract_error("active request gauge is out of range"))?,
            connected_clients: runtime.connected_clients(),
            queued_requests: u32::try_from(counters.queued_requests())
                .map_err(|_| telemetry_contract_error("queued request gauge is out of range"))?,
            counters: [
                counters.requests_received(),
                counters.requests_admitted(),
                counters.requests_completed(),
                counters.requests_failed(),
                counters.requests_cancelled(),
                counters.requests_retried(),
                counters.input_tokens(),
                counters.output_tokens(),
                counters.cached_tokens(),
                counters.queue_milliseconds(),
                counters.ttft_milliseconds(),
                counters.decode_milliseconds(),
                counters.exact_token_requests(),
                counters.prefix_cache_hits(),
                runtime.usage_records_dropped(),
                runtime.usage_write_errors(),
            ],
        })
    }

    // Returns whether every monotonic counter follows one prior successful publication.
    fn follows(&self, previous: &Self) -> bool {
        self.counters
            .iter()
            .zip(previous.counters.iter())
            .all(|(current, previous)| current >= previous)
    }

    // Serializes the unchanged Python and Watchdog telemetry-v2 text vocabulary.
    fn payload(&self) -> Vec<u8> {
        format!(
            concat!(
                "version=2\n",
                "active_requests={}\n",
                "cached_tokens={}\n",
                "connected_clients={}\n",
                "decode_milliseconds={}\n",
                "exact_token_requests={}\n",
                "input_tokens={}\n",
                "output_tokens={}\n",
                "prefix_cache_hits={}\n",
                "queue_milliseconds={}\n",
                "queued_requests={}\n",
                "requests_admitted={}\n",
                "requests_cancelled={}\n",
                "requests_completed={}\n",
                "requests_failed={}\n",
                "requests_received={}\n",
                "requests_retried={}\n",
                "ttft_milliseconds={}\n",
                "usage_records_dropped={}\n",
                "usage_write_errors={}\n"
            ),
            self.active_requests,
            self.counters[8],
            self.connected_clients,
            self.counters[11],
            self.counters[12],
            self.counters[6],
            self.counters[7],
            self.counters[13],
            self.counters[9],
            self.queued_requests,
            self.counters[1],
            self.counters[4],
            self.counters[2],
            self.counters[3],
            self.counters[0],
            self.counters[5],
            self.counters[10],
            self.counters[14],
            self.counters[15],
        )
        .into_bytes()
    }
}

// Retains only the last successful process-local telemetry sequence.
struct GatewayTelemetryPublisherState {
    observed_at: UnixMilliseconds,
    record: GatewayTelemetryV2Record,
}

// Publishes Watchdog-compatible telemetry-v2 through one private stable path.
pub struct SystemGatewayTelemetryPublisher {
    path: PathBuf,
    owner_user_id: u32,
    runtime: Arc<dyn GatewayTelemetryRuntimeCounterProvider>,
    files: Arc<dyn GatewayTelemetryAtomicFileIo>,
    temporary_identities: Arc<dyn GatewayTelemetryTemporaryIdentityProvider>,
    state: Mutex<Option<GatewayTelemetryPublisherState>>,
}

impl SystemGatewayTelemetryPublisher {
    // Creates one production publisher over an exact absolute installed telemetry path.
    pub fn new(
        path: PathBuf,
        owner_user_id: u32,
        runtime: Arc<dyn GatewayTelemetryRuntimeCounterProvider>,
    ) -> Result<Self, GatewayError> {
        Self::with_providers(
            path,
            owner_user_id,
            runtime,
            Arc::new(SystemGatewayTelemetryAtomicFileIo),
            Arc::new(SystemGatewayTelemetryTemporaryIdentityProvider),
        )
    }

    // Creates one publisher around injected runtime, filesystem, and identity boundaries.
    fn with_providers(
        path: PathBuf,
        owner_user_id: u32,
        runtime: Arc<dyn GatewayTelemetryRuntimeCounterProvider>,
        files: Arc<dyn GatewayTelemetryAtomicFileIo>,
        temporary_identities: Arc<dyn GatewayTelemetryTemporaryIdentityProvider>,
    ) -> Result<Self, GatewayError> {
        validate_telemetry_path(&path)?;
        Ok(Self {
            path,
            owner_user_id,
            runtime,
            files,
            temporary_identities,
            state: Mutex::new(None),
        })
    }
}

impl GatewayTelemetryPublisher for SystemGatewayTelemetryPublisher {
    // Publishes one complete monotonic record and advances state only after durable replacement.
    fn publish_atomically(&self, snapshot: &GatewayTelemetrySnapshot) -> Result<(), GatewayError> {
        let runtime = self.runtime.counters().map_err(|_| {
            GatewayError::provider(
                "telemetry_runtime_counters",
                "runtime counters are unavailable",
            )
        })?;
        let record = GatewayTelemetryV2Record::from_snapshot(snapshot, runtime)?;
        let payload = record.payload();
        if payload.len() > TELEMETRY_V2_MAX_BYTES {
            return Err(telemetry_contract_error(
                "telemetry payload exceeds its bound",
            ));
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| GatewayError::StateUnavailable)?;
        if state.as_ref().is_some_and(|previous| {
            snapshot.observed_at().value() < previous.observed_at.value()
                || !record.follows(&previous.record)
        }) {
            return Err(telemetry_contract_error("telemetry sequence regressed"));
        }
        let temporary_identity = self.temporary_identities.identity()?;
        self.files.replace(
            &self.path,
            &payload,
            self.owner_user_id,
            &temporary_identity,
        )?;
        *state = Some(GatewayTelemetryPublisherState {
            observed_at: snapshot.observed_at(),
            record,
        });
        Ok(())
    }
}

// Writes, verifies, and atomically replaces one telemetry file within its validated parent.
fn replace_telemetry_file(
    temporary: &Path,
    destination: &Path,
    payload: &[u8],
    owner_user_id: u32,
    previous: Option<GatewayTelemetryFileIdentity>,
) -> Result<(), GatewayError> {
    let parent = destination
        .parent()
        .ok_or_else(|| telemetry_file_error("telemetry path is invalid"))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(temporary)
        .map_err(|_| telemetry_file_error("temporary telemetry file could not be created"))?;
    let result = (|| {
        file.write_all(payload)
            .and_then(|_| file.sync_all())
            .map_err(|_| telemetry_file_error("temporary telemetry file could not be written"))?;
        validate_telemetry_file_metadata(
            &file
                .metadata()
                .map_err(|_| telemetry_file_error("temporary telemetry metadata is unavailable"))?,
            owner_user_id,
            payload.len(),
        )?;
        if telemetry_file_identity(destination, owner_user_id)? != previous {
            return Err(telemetry_file_error("telemetry destination changed"));
        }
        fs::rename(temporary, destination)
            .map_err(|_| telemetry_file_error("telemetry file could not be replaced"))?;
        sync_telemetry_directory(parent)
    })();
    drop(file);
    if result.is_err() {
        cleanup_telemetry_temporary(temporary);
    }
    result
}

// Returns one optional safe telemetry descriptor identity without following links.
fn telemetry_file_identity(
    path: &Path,
    owner_user_id: u32,
) -> Result<Option<GatewayTelemetryFileIdentity>, GatewayError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(telemetry_file_error("telemetry metadata is unavailable")),
    };
    validate_telemetry_file_metadata(
        &metadata,
        owner_user_id,
        usize::try_from(metadata.len()).unwrap_or(usize::MAX),
    )?;
    Ok(Some(GatewayTelemetryFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }))
}

// Requires one absolute stable telemetry filename with no parent traversal.
fn validate_telemetry_path(path: &Path) -> Result<(), GatewayError> {
    let file_name = path.file_name().and_then(|name| name.to_str());
    if !path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
        || file_name.is_none_or(|name| {
            name.is_empty()
                || name.len() > 255
                || matches!(name, "." | "..")
                || name.contains('/')
                || name.contains('\0')
        })
    {
        return Err(telemetry_file_error("telemetry path is invalid"));
    }
    Ok(())
}

// Requires one owner-only real directory before any telemetry mutation.
fn validate_telemetry_directory(path: &Path, owner_user_id: u32) -> Result<(), GatewayError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| telemetry_file_error("telemetry directory is unavailable"))?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != owner_user_id
        || metadata.mode() & 0o077 != 0
    {
        return Err(telemetry_file_error(
            "telemetry directory identity is unsafe",
        ));
    }
    Ok(())
}

// Requires one exact mode-0600 single-link regular telemetry file identity.
fn validate_telemetry_file_metadata(
    metadata: &fs::Metadata,
    owner_user_id: u32,
    expected_bytes: usize,
) -> Result<(), GatewayError> {
    if !metadata.file_type().is_file()
        || metadata.uid() != owner_user_id
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() != expected_bytes as u64
        || metadata.len() == 0
        || metadata.len() > TELEMETRY_V2_MAX_BYTES as u64
        || metadata.dev() == 0
        || metadata.ino() == 0
    {
        return Err(telemetry_file_error("telemetry file identity is unsafe"));
    }
    Ok(())
}

// Removes only one known same-directory temporary telemetry path after failure.
fn cleanup_telemetry_temporary(path: &Path) {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() && metadata.nlink() == 1 => {
            let _ = fs::remove_file(path);
            if let Some(parent) = path.parent() {
                let _ = sync_telemetry_directory(parent);
            }
        }
        Ok(_) | Err(_) => {}
    }
}

// Syncs one validated telemetry directory after replacement or cleanup.
fn sync_telemetry_directory(path: &Path) -> Result<(), GatewayError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| telemetry_file_error("telemetry directory could not be synchronized"))
}

// Requires one canonical random temporary-file identity.
fn is_temporary_identity(identity: &str) -> bool {
    identity.len() == TELEMETRY_TEMPORARY_IDENTITY_BYTES * 2
        && identity
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

// Creates one stable telemetry contract failure.
const fn telemetry_contract_error(reason: &'static str) -> GatewayError {
    GatewayError::InvalidContract { reason }
}

// Creates one redacted telemetry filesystem failure.
const fn telemetry_file_error(reason: &'static str) -> GatewayError {
    GatewayError::provider("telemetry_file", reason)
}

// Discards snapshots until daemon composition injects its native atomic publisher.
pub(crate) struct DiscardingGatewayTelemetryPublisher;

impl GatewayTelemetryPublisher for DiscardingGatewayTelemetryPublisher {
    // Accepts one snapshot without performing external I/O.
    fn publish_atomically(&self, _snapshot: &GatewayTelemetrySnapshot) -> Result<(), GatewayError> {
        Ok(())
    }
}

// Carries request durations already observed by the execution boundary.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct GatewayTelemetryTiming {
    queue_milliseconds: u64,
    ttft_milliseconds: u64,
    decode_milliseconds: u64,
}

impl GatewayTelemetryTiming {
    // Creates timing from optional ordered dispatch, first-byte, and completion observations.
    pub(crate) fn from_observations(
        queue_milliseconds: u64,
        dispatched_at: Option<u64>,
        first_byte_at: Option<u64>,
        completed_at: Option<u64>,
    ) -> Self {
        let ttft_milliseconds = dispatched_at
            .zip(first_byte_at)
            .map_or(0, |(dispatched, first)| first.saturating_sub(dispatched));
        let decode_milliseconds = first_byte_at
            .zip(completed_at)
            .map_or(0, |(first, completed)| completed.saturating_sub(first));
        Self {
            queue_milliseconds,
            ttft_milliseconds,
            decode_milliseconds,
        }
    }
}

// Stores one placement-group identity and its cumulative bounded counters.
struct PlacementGroupTelemetry {
    model: LogicalModelName,
    endpoint_node_id: NodeId,
    max_active_requests: u64,
    counters: GatewayPlacementGroupCounters,
}

// Stores one token delta in the bounded five-second activity window.
struct PlacementGroupSample {
    observed_at: u64,
    placement_group_id: PlacementGroupId,
    input_tokens: u64,
    output_tokens: u64,
    cached_tokens: u64,
}

// Owns secret-free counters, bounded activity, and publisher readiness under Gateway state.
#[derive(Default)]
pub(crate) struct GatewayTelemetryState {
    counters: GatewayTelemetryCounters,
    placement_groups: BTreeMap<PlacementGroupId, PlacementGroupTelemetry>,
    placement_group_samples: VecDeque<PlacementGroupSample>,
    last_publish_success: Option<u64>,
    last_publish_failure: Option<u64>,
}

impl GatewayTelemetryState {
    // Records one request entering an authorized Gateway surface.
    pub(crate) fn record_received(&mut self) {
        increment(&mut self.counters.requests_received, 1);
    }

    // Records one terminal failure before a placement group owns the request.
    pub(crate) fn record_unrouted_failure(&mut self) {
        self.record_unrouted_failure_with_timing(GatewayTelemetryTiming::default());
    }

    // Records one terminal unrouted failure with its accumulated queue duration.
    pub(crate) fn record_unrouted_failure_with_timing(&mut self, timing: GatewayTelemetryTiming) {
        increment(&mut self.counters.requests_failed, 1);
        self.record_timing(timing);
    }

    // Records the first placement-group reservation for one request.
    pub(crate) fn record_admitted(&mut self, route: &GatewayRoute) {
        increment(&mut self.counters.requests_admitted, 1);
        if let Some(group) = self.group(route) {
            increment(&mut group.counters.requests_admitted, 1);
        }
    }

    // Records one successful pre-output move away from a failed placement group.
    pub(crate) fn record_retried(&mut self, route: &GatewayRoute) {
        increment(&mut self.counters.requests_retried, 1);
        if let Some(group) = self.group(route) {
            increment(&mut group.counters.requests_retried, 1);
        }
    }

    // Records one completed exact-token request and its terminal durations.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn record_completed(
        &mut self,
        route: &GatewayRoute,
        observed_at: u64,
        timing: GatewayTelemetryTiming,
        input_tokens: u64,
        output_tokens: u64,
        cached_tokens: u64,
        exact_tokens: bool,
    ) {
        increment(&mut self.counters.requests_completed, 1);
        increment(&mut self.counters.input_tokens, input_tokens);
        increment(&mut self.counters.output_tokens, output_tokens);
        increment(&mut self.counters.cached_tokens, cached_tokens);
        self.record_timing(timing);
        if exact_tokens {
            increment(&mut self.counters.exact_token_requests, 1);
        }
        if cached_tokens > 0 {
            increment(&mut self.counters.prefix_cache_hits, 1);
        }
        if let Some(group) = self.group(route) {
            increment(&mut group.counters.requests_completed, 1);
            increment(&mut group.counters.input_tokens, input_tokens);
            increment(&mut group.counters.output_tokens, output_tokens);
            increment(&mut group.counters.cached_tokens, cached_tokens);
        }
        self.record_sample(
            route.placement_group_id().clone(),
            observed_at,
            input_tokens,
            output_tokens,
            cached_tokens,
        );
    }

    // Records one terminal placement-group failure and its observed durations.
    pub(crate) fn record_failed(&mut self, route: &GatewayRoute, timing: GatewayTelemetryTiming) {
        increment(&mut self.counters.requests_failed, 1);
        self.record_timing(timing);
        if let Some(group) = self.group(route) {
            increment(&mut group.counters.requests_failed, 1);
        }
    }

    // Records one explicit cancellation and its observed durations.
    pub(crate) fn record_cancelled(
        &mut self,
        route: Option<&GatewayRoute>,
        timing: GatewayTelemetryTiming,
    ) {
        increment(&mut self.counters.requests_cancelled, 1);
        self.record_timing(timing);
        if let Some(group) = route.and_then(|route| self.group(route)) {
            increment(&mut group.counters.requests_cancelled, 1);
        }
    }

    // Returns one immutable snapshot while pruning expired rate samples.
    pub(crate) fn snapshot(
        &mut self,
        observed_at: UnixMilliseconds,
        active_requests: usize,
        queued_models: impl Iterator<Item = LogicalModelName>,
        route_active: &HashMap<PlacementGroupId, u32>,
    ) -> GatewayTelemetrySnapshot {
        self.prune_samples(observed_at.value());
        let mut counters = self.counters.clone();
        counters.active_requests = usize_to_u64(active_requests);

        let mut queued = BTreeMap::<LogicalModelName, u64>::new();
        for model in queued_models {
            increment(queued.entry(model).or_default(), 1);
        }
        counters.queued_requests = queued.values().copied().fold(0, u64::saturating_add);
        let models = queued
            .into_iter()
            .map(|(model, queued_requests)| GatewayModelActivity {
                model,
                queued_requests,
            })
            .collect();

        let recent = self.recent_sample_totals();
        let placement_groups = self
            .placement_groups
            .iter()
            .map(|(placement_group_id, group)| {
                let (input_tokens, output_tokens, cached_tokens, first_observed_at) =
                    recent.get(placement_group_id).copied().unwrap_or_default();
                let elapsed_milliseconds = observed_at
                    .value()
                    .saturating_sub(first_observed_at)
                    .max(1_000);
                let rate = |tokens: u64| (tokens as f64) * 1_000.0 / (elapsed_milliseconds as f64);
                GatewayPlacementGroupActivity {
                    placement_group_id: placement_group_id.clone(),
                    model: group.model.clone(),
                    endpoint_node_id: group.endpoint_node_id.clone(),
                    active_requests: u64::from(
                        route_active.get(placement_group_id).copied().unwrap_or(0),
                    ),
                    max_active_requests: group.max_active_requests,
                    counters: group.counters.clone(),
                    rates: GatewayPlacementGroupRates {
                        input_tokens_per_second: rate(input_tokens),
                        output_tokens_per_second: rate(output_tokens),
                        cached_tokens_per_second: rate(cached_tokens),
                    },
                }
            })
            .collect();

        GatewayTelemetrySnapshot {
            observed_at,
            counters,
            models,
            placement_groups,
        }
    }

    // Records successful external publication and clears an older failure state.
    pub(crate) fn publisher_did_succeed(&mut self, observed_at: u64) {
        self.last_publish_success = Some(observed_at);
        self.last_publish_failure = None;
    }

    // Records one redacted external publication failure.
    pub(crate) fn publisher_did_fail(&mut self, observed_at: u64) {
        self.last_publish_failure = Some(observed_at);
    }

    // Returns freshness-based publisher readiness without exposing native error details.
    pub(crate) fn health(&self, observed_at: u64) -> GatewayTelemetryHealth {
        let healthy = self.last_publish_success.is_some_and(|success| {
            self.last_publish_failure.is_none()
                && observed_at >= success
                && observed_at.saturating_sub(success) <= TELEMETRY_STALE_MILLISECONDS
        });
        GatewayTelemetryHealth {
            healthy,
            last_success_at: self.last_publish_success.map(UnixMilliseconds::new),
            last_failure_at: self.last_publish_failure.map(UnixMilliseconds::new),
        }
    }

    // Adds terminal duration values with saturating monotonic counters.
    fn record_timing(&mut self, timing: GatewayTelemetryTiming) {
        increment(
            &mut self.counters.queue_milliseconds,
            timing.queue_milliseconds,
        );
        increment(
            &mut self.counters.ttft_milliseconds,
            timing.ttft_milliseconds,
        );
        increment(
            &mut self.counters.decode_milliseconds,
            timing.decode_milliseconds,
        );
    }

    // Returns one existing group or inserts it while respecting the identity bound.
    fn group(&mut self, route: &GatewayRoute) -> Option<&mut PlacementGroupTelemetry> {
        let placement_group_id = route.placement_group_id().clone();
        if !self.placement_groups.contains_key(&placement_group_id) {
            if self.placement_groups.len() >= MAX_PLACEMENT_GROUP_ACTIVITY {
                return None;
            }
            self.placement_groups.insert(
                placement_group_id.clone(),
                PlacementGroupTelemetry {
                    model: route.model().clone(),
                    endpoint_node_id: route.endpoint_node_id().clone(),
                    max_active_requests: u64::from(route.max_active_requests().get()),
                    counters: GatewayPlacementGroupCounters::default(),
                },
            );
        }
        let group = self.placement_groups.get_mut(&placement_group_id)?;
        group.model = route.model().clone();
        group.endpoint_node_id = route.endpoint_node_id().clone();
        group.max_active_requests = u64::from(route.max_active_requests().get());
        Some(group)
    }

    // Appends one bounded token sample and discards only the oldest retained sample.
    fn record_sample(
        &mut self,
        placement_group_id: PlacementGroupId,
        observed_at: u64,
        input_tokens: u64,
        output_tokens: u64,
        cached_tokens: u64,
    ) {
        if !self.placement_groups.contains_key(&placement_group_id) {
            return;
        }
        self.placement_group_samples
            .push_back(PlacementGroupSample {
                observed_at,
                placement_group_id,
                input_tokens,
                output_tokens,
                cached_tokens,
            });
        while self.placement_group_samples.len() > MAX_PLACEMENT_GROUP_SAMPLES {
            self.placement_group_samples.pop_front();
        }
    }

    // Removes token-rate samples older than the closed five-second window.
    fn prune_samples(&mut self, observed_at: u64) {
        let cutoff = observed_at.saturating_sub(PLACEMENT_GROUP_RATE_WINDOW_MILLISECONDS);
        while self
            .placement_group_samples
            .front()
            .is_some_and(|sample| sample.observed_at < cutoff)
        {
            self.placement_group_samples.pop_front();
        }
    }

    // Aggregates the retained token window by placement group without exposing samples.
    fn recent_sample_totals(&self) -> HashMap<PlacementGroupId, (u64, u64, u64, u64)> {
        let mut totals = HashMap::<PlacementGroupId, (u64, u64, u64, u64)>::new();
        for sample in &self.placement_group_samples {
            let row = totals.entry(sample.placement_group_id.clone()).or_insert((
                0,
                0,
                0,
                sample.observed_at,
            ));
            row.0 = row.0.saturating_add(sample.input_tokens);
            row.1 = row.1.saturating_add(sample.output_tokens);
            row.2 = row.2.saturating_add(sample.cached_tokens);
            row.3 = row.3.min(sample.observed_at);
        }
        totals
    }
}

// Adds one non-negative delta without wrapping telemetry across process lifetime.
fn increment(value: &mut u64, delta: u64) {
    *value = value.saturating_add(delta);
}

// Converts a bounded in-memory collection size without platform-width truncation.
fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod native_tests {
    use std::collections::VecDeque;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static TEST_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    // Supplies ordered runtime-counter results to one deterministic publisher.
    struct RuntimeCounters {
        values: Mutex<VecDeque<Result<GatewayTelemetryRuntimeCounters, GatewayError>>>,
    }

    impl GatewayTelemetryRuntimeCounterProvider for RuntimeCounters {
        // Returns the next runtime observation without consulting resident listeners.
        fn counters(&self) -> Result<GatewayTelemetryRuntimeCounters, GatewayError> {
            self.values
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| Ok(GatewayTelemetryRuntimeCounters::default()))
        }
    }

    // Stores mock atomic replacement state and one optional partial failure.
    #[derive(Default)]
    struct AtomicFileIo {
        state: Mutex<AtomicFileIoState>,
    }

    #[derive(Default)]
    struct AtomicFileIoState {
        payload: Option<Vec<u8>>,
        fail_next: bool,
        attempted_payload: Option<Vec<u8>>,
        temporary_was_cleaned: bool,
    }

    impl GatewayTelemetryAtomicFileIo for AtomicFileIo {
        // Replaces one mock payload or simulates a cleaned partial write before publication.
        fn replace(
            &self,
            _path: &Path,
            payload: &[u8],
            _owner_user_id: u32,
            _temporary_identity: &str,
        ) -> Result<(), GatewayError> {
            let mut state = self.state.lock().unwrap();
            state.attempted_payload = Some(payload.to_vec());
            if state.fail_next {
                state.fail_next = false;
                state.temporary_was_cleaned = true;
                return Err(telemetry_file_error("mock replacement failed"));
            }
            state.payload = Some(payload.to_vec());
            Ok(())
        }
    }

    // Supplies one fixed canonical temporary identity or a redacted entropy failure.
    struct TemporaryIdentity {
        fails: bool,
    }

    impl GatewayTelemetryTemporaryIdentityProvider for TemporaryIdentity {
        // Returns one fixed valid identity unless failure was requested.
        fn identity(&self) -> Result<String, GatewayError> {
            if self.fails {
                return Err(telemetry_file_error("temporary identity is unavailable"));
            }
            Ok("a".repeat(32))
        }
    }

    // Returns one manager snapshot whose monotonic counters all share a base value.
    fn snapshot(observed_at: u64, base: u64) -> GatewayTelemetrySnapshot {
        GatewayTelemetrySnapshot {
            observed_at: UnixMilliseconds::new(observed_at),
            counters: GatewayTelemetryCounters {
                requests_received: base,
                requests_admitted: base + 1,
                requests_completed: base + 2,
                requests_failed: base + 3,
                requests_cancelled: base + 4,
                requests_retried: base + 5,
                active_requests: 2,
                queued_requests: 3,
                input_tokens: base + 6,
                output_tokens: base + 7,
                cached_tokens: base + 8,
                queue_milliseconds: base + 9,
                ttft_milliseconds: base + 10,
                decode_milliseconds: base + 11,
                exact_token_requests: base + 12,
                prefix_cache_hits: base + 13,
            },
            models: Vec::new(),
            placement_groups: Vec::new(),
        }
    }

    // Returns one deterministic publisher and its inspectable atomic file boundary.
    fn publisher(
        runtime_values: Vec<Result<GatewayTelemetryRuntimeCounters, GatewayError>>,
    ) -> (SystemGatewayTelemetryPublisher, Arc<AtomicFileIo>) {
        let files = Arc::new(AtomicFileIo::default());
        let publisher = SystemGatewayTelemetryPublisher::with_providers(
            PathBuf::from("/private/li_gateway_telemetry_v2"),
            501,
            Arc::new(RuntimeCounters {
                values: Mutex::new(runtime_values.into()),
            }),
            files.clone(),
            Arc::new(TemporaryIdentity { fails: false }),
        )
        .unwrap();
        (publisher, files)
    }

    // Creates one unique owner-only directory for real native telemetry I/O.
    fn test_directory() -> PathBuf {
        let sequence = TEST_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "li_gateway_telemetry_{}_{}",
            std::process::id(),
            sequence
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    // Removes one known test directory and its direct test-owned entries.
    fn remove_test_directory(path: &Path) {
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                let child = entry.path();
                let _ = if child.is_dir() {
                    fs::remove_dir(child)
                } else {
                    fs::remove_file(child)
                };
            }
        }
        let _ = fs::remove_dir(path);
    }

    #[test]
    // Emits the exact unchanged telemetry-v2 Watchdog field vocabulary and ordering.
    fn publisher_emits_exact_watchdog_telemetry_v2() {
        let runtime = GatewayTelemetryRuntimeCounters::new(4, 18, 19);
        let (publisher, files) = publisher(vec![Ok(runtime)]);
        publisher.publish_atomically(&snapshot(1_000, 1)).unwrap();
        let payload = files.state.lock().unwrap().payload.clone().unwrap();
        assert_eq!(
            String::from_utf8(payload).unwrap(),
            concat!(
                "version=2\n",
                "active_requests=2\n",
                "cached_tokens=9\n",
                "connected_clients=4\n",
                "decode_milliseconds=12\n",
                "exact_token_requests=13\n",
                "input_tokens=7\n",
                "output_tokens=8\n",
                "prefix_cache_hits=14\n",
                "queue_milliseconds=10\n",
                "queued_requests=3\n",
                "requests_admitted=2\n",
                "requests_cancelled=5\n",
                "requests_completed=3\n",
                "requests_failed=4\n",
                "requests_received=1\n",
                "requests_retried=6\n",
                "ttft_milliseconds=11\n",
                "usage_records_dropped=18\n",
                "usage_write_errors=19\n"
            )
        );
    }

    #[test]
    // Rejects counter or observation-time regression after one successful process-local publish.
    fn publisher_rejects_sequence_regression() {
        let (publisher, _) = publisher(vec![
            Ok(GatewayTelemetryRuntimeCounters::new(1, 20, 20)),
            Ok(GatewayTelemetryRuntimeCounters::new(0, 19, 20)),
            Ok(GatewayTelemetryRuntimeCounters::new(0, 21, 21)),
        ]);
        publisher.publish_atomically(&snapshot(2_000, 20)).unwrap();
        assert_eq!(
            publisher
                .publish_atomically(&snapshot(2_001, 19))
                .unwrap_err(),
            telemetry_contract_error("telemetry sequence regressed")
        );
        assert_eq!(
            publisher
                .publish_atomically(&snapshot(1_999, 21))
                .unwrap_err(),
            telemetry_contract_error("telemetry sequence regressed")
        );
    }

    #[test]
    // Preserves the prior publication and sequence after a cleaned partial atomic failure.
    fn publisher_rolls_back_partial_replacement() {
        let (publisher, files) = publisher(vec![
            Ok(GatewayTelemetryRuntimeCounters::default()),
            Ok(GatewayTelemetryRuntimeCounters::default()),
            Ok(GatewayTelemetryRuntimeCounters::default()),
        ]);
        publisher.publish_atomically(&snapshot(1_000, 10)).unwrap();
        let previous = files.state.lock().unwrap().payload.clone().unwrap();
        files.state.lock().unwrap().fail_next = true;
        assert!(publisher.publish_atomically(&snapshot(1_001, 11)).is_err());
        let state = files.state.lock().unwrap();
        assert_eq!(state.payload.as_ref(), Some(&previous));
        assert!(state.temporary_was_cleaned);
        drop(state);
        assert!(publisher.publish_atomically(&snapshot(1_001, 10)).is_ok());
    }

    #[test]
    // Rejects runtime-counter and temporary-identity failures before visible replacement.
    fn publisher_rejects_injected_provider_failures() {
        let (publisher, files) = publisher(vec![Err(GatewayError::provider(
            "runtime_counters",
            "unavailable",
        ))]);
        assert!(publisher.publish_atomically(&snapshot(1_000, 1)).is_err());
        assert!(files.state.lock().unwrap().payload.is_none());

        let publisher = SystemGatewayTelemetryPublisher::with_providers(
            PathBuf::from("/private/li_gateway_telemetry_v2"),
            501,
            Arc::new(RuntimeCounters {
                values: Mutex::new(vec![Ok(GatewayTelemetryRuntimeCounters::default())].into()),
            }),
            Arc::new(AtomicFileIo::default()),
            Arc::new(TemporaryIdentity { fails: true }),
        )
        .unwrap();
        assert!(publisher.publish_atomically(&snapshot(1_000, 1)).is_err());
    }

    #[test]
    // Rejects relative and traversing telemetry paths before any provider observation.
    fn publisher_rejects_unsafe_paths() {
        let runtime = Arc::new(RuntimeCounters {
            values: Mutex::new(VecDeque::new()),
        });
        assert!(SystemGatewayTelemetryPublisher::new(
            PathBuf::from("relative/telemetry"),
            501,
            runtime.clone(),
        )
        .is_err());
        assert!(SystemGatewayTelemetryPublisher::new(
            PathBuf::from("/private/../tmp/telemetry"),
            501,
            runtime,
        )
        .is_err());
    }

    #[test]
    // Replaces a real private file atomically and permits a fresh process to reset counters.
    fn system_publisher_changes_file_identity_across_restart() {
        let directory = test_directory();
        let path = directory.join("li_gateway_telemetry_v2");
        let owner_user_id = unsafe { libc::geteuid() };
        let runtime: Arc<dyn GatewayTelemetryRuntimeCounterProvider> = Arc::new(RuntimeCounters {
            values: Mutex::new(
                vec![
                    Ok(GatewayTelemetryRuntimeCounters::default()),
                    Ok(GatewayTelemetryRuntimeCounters::default()),
                ]
                .into(),
            ),
        });
        let first =
            SystemGatewayTelemetryPublisher::new(path.clone(), owner_user_id, runtime.clone())
                .unwrap();
        first.publish_atomically(&snapshot(2_000, 50)).unwrap();
        let first_inode = fs::symlink_metadata(&path).unwrap().ino();
        let restarted =
            SystemGatewayTelemetryPublisher::new(path.clone(), owner_user_id, runtime).unwrap();
        restarted.publish_atomically(&snapshot(3_000, 1)).unwrap();
        let metadata = fs::symlink_metadata(&path).unwrap();
        assert_ne!(metadata.ino(), first_inode);
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert_eq!(metadata.nlink(), 1);
        remove_test_directory(&directory);
    }

    #[test]
    // Rejects loose modes, links, and mismatched ownership before replacing existing bytes.
    fn system_publisher_rejects_unsafe_destination_identity() {
        let directory = test_directory();
        let owner_user_id = unsafe { libc::geteuid() };
        let runtime = || {
            Arc::new(RuntimeCounters {
                values: Mutex::new(vec![Ok(GatewayTelemetryRuntimeCounters::default())].into()),
            }) as Arc<dyn GatewayTelemetryRuntimeCounterProvider>
        };

        let loose = directory.join("loose");
        fs::write(&loose, b"unsafe").unwrap();
        fs::set_permissions(&loose, fs::Permissions::from_mode(0o644)).unwrap();
        let publisher =
            SystemGatewayTelemetryPublisher::new(loose.clone(), owner_user_id, runtime()).unwrap();
        assert!(publisher.publish_atomically(&snapshot(1_000, 1)).is_err());
        assert_eq!(fs::read(&loose).unwrap(), b"unsafe");

        let linked = directory.join("linked");
        let second_link = directory.join("linked_second");
        fs::write(&linked, b"unsafe").unwrap();
        fs::set_permissions(&linked, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&linked, &second_link).unwrap();
        let publisher =
            SystemGatewayTelemetryPublisher::new(linked.clone(), owner_user_id, runtime()).unwrap();
        assert!(publisher.publish_atomically(&snapshot(1_000, 1)).is_err());

        let symlink = directory.join("symlink");
        std::os::unix::fs::symlink(&loose, &symlink).unwrap();
        let publisher =
            SystemGatewayTelemetryPublisher::new(symlink, owner_user_id, runtime()).unwrap();
        assert!(publisher.publish_atomically(&snapshot(1_000, 1)).is_err());

        let ownership = directory.join("ownership");
        let publisher = SystemGatewayTelemetryPublisher::new(
            ownership.clone(),
            owner_user_id.saturating_add(1),
            runtime(),
        )
        .unwrap();
        assert!(publisher.publish_atomically(&snapshot(1_000, 1)).is_err());
        assert!(!ownership.exists());
        remove_test_directory(&directory);
    }

    #[test]
    // Leaves a pre-existing colliding temporary file untouched and publishes nothing.
    fn system_publisher_does_not_remove_temporary_conflicts() {
        let directory = test_directory();
        let path = directory.join("telemetry");
        let temporary = directory.join(format!(".telemetry.{}.tmp", "a".repeat(32)));
        fs::write(&temporary, b"owned conflict").unwrap();
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)).unwrap();
        let publisher = SystemGatewayTelemetryPublisher::with_providers(
            path.clone(),
            unsafe { libc::geteuid() },
            Arc::new(RuntimeCounters {
                values: Mutex::new(vec![Ok(GatewayTelemetryRuntimeCounters::default())].into()),
            }),
            Arc::new(SystemGatewayTelemetryAtomicFileIo),
            Arc::new(TemporaryIdentity { fails: false }),
        )
        .unwrap();
        assert!(publisher.publish_atomically(&snapshot(1_000, 1)).is_err());
        assert_eq!(fs::read(&temporary).unwrap(), b"owned conflict");
        assert!(!path.exists());
        remove_test_directory(&directory);
    }
}
