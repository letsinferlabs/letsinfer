// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use li_core_interface::{PlacementGroupId, Sha256Digest, UnixMilliseconds};
use sha2::{Digest, Sha256};

use crate::{
    LinuxPlacementExecutionProvider, LinuxPlacementExecutionState, PlacementError,
    VersionedPlacementRecord,
};

// Observes one complete platform-native process generation without lifecycle mutation.
pub trait PlacementBenchmarkProcessProvider: Send + Sync {
    // Returns one aggregate PID-reuse-safe generation for every placement in a running group.
    fn generation(
        &self,
        running: &VersionedPlacementRecord,
    ) -> Result<Sha256Digest, PlacementError>;
}

// Projects existing protected Linux container observations into one aggregate generation.
pub struct LinuxPlacementBenchmarkProcessProvider {
    execution: Arc<dyn LinuxPlacementExecutionProvider>,
}

impl LinuxPlacementBenchmarkProcessProvider {
    // Creates one observer over the same execution provider owned by LinuxPlacementExecutor.
    pub const fn new(execution: Arc<dyn LinuxPlacementExecutionProvider>) -> Self {
        Self { execution }
    }
}

impl PlacementBenchmarkProcessProvider for LinuxPlacementBenchmarkProcessProvider {
    // Hashes exact container, PID/start, boot, and cgroup identities in placement order.
    fn generation(
        &self,
        running: &VersionedPlacementRecord,
    ) -> Result<Sha256Digest, PlacementError> {
        if running.record().placements().is_empty() {
            return Err(PlacementError::ExecutionUnavailable);
        }
        let mut digest = Sha256::new();
        framed_digest_field(&mut digest, "li-placement-linux-process-generation-v1");
        framed_digest_field(
            &mut digest,
            running.record().group().placement_group_id().as_str(),
        );
        for placement in running.record().placements() {
            let observation = self.execution.observe(placement)?;
            let process = observation
                .process()
                .filter(|_| observation.state() == LinuxPlacementExecutionState::Running)
                .ok_or(PlacementError::ExecutionUnavailable)?;
            for value in [
                placement.placement_id().as_str().to_string(),
                process.container_name().as_str().to_string(),
                process.container_id().as_str().to_string(),
                process.process_id().to_string(),
                process.process_start_ticks().to_string(),
                process.boot_id().as_str().to_string(),
                process.cgroup().to_string(),
            ] {
                framed_digest_field(&mut digest, &value);
            }
        }
        Sha256Digest::parse(&format!("{:x}", digest.finalize()))
            .map_err(|_| PlacementError::ExecutionUnavailable)
    }
}

// Carries the exact process and prefix-store generations observed on one running group.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlacementBenchmarkGenerations {
    process_generation_sha256: Sha256Digest,
    store_generation_sha256: Sha256Digest,
}

// Identifies one restart-safe benchmark isolation transaction for an exact placement group.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlacementBenchmarkIsolationRequest {
    isolation_id: Sha256Digest,
    placement_group_id: PlacementGroupId,
}

impl PlacementBenchmarkIsolationRequest {
    // Creates one opaque transaction identity without importing BenchmarkManager concepts.
    pub const fn new(isolation_id: Sha256Digest, placement_group_id: PlacementGroupId) -> Self {
        Self {
            isolation_id,
            placement_group_id,
        }
    }

    // Returns the idempotency identity supplied by the Application scheduler boundary.
    pub const fn isolation_id(&self) -> &Sha256Digest {
        &self.isolation_id
    }

    // Returns the exact placement group whose resident cache must be restored.
    pub const fn placement_group_id(&self) -> &PlacementGroupId {
        &self.placement_group_id
    }
}

// Proves the original resident process/store generations captured before benchmark mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlacementBenchmarkIsolationReceipt {
    request: PlacementBenchmarkIsolationRequest,
    prepared_revision: u64,
    resident_process_generation_sha256: Sha256Digest,
    resident_store_generation_sha256: Sha256Digest,
    receipt_sha256: Sha256Digest,
}

impl PlacementBenchmarkIsolationReceipt {
    // Creates one exact resident snapshot before the first cache or process rotation.
    pub fn new(
        request: PlacementBenchmarkIsolationRequest,
        prepared_revision: u64,
        resident_process_generation_sha256: Sha256Digest,
        resident_store_generation_sha256: Sha256Digest,
    ) -> Result<Self, PlacementError> {
        if prepared_revision == 0 {
            return Err(PlacementError::InvalidRequest {
                reason: "benchmark isolation revision is invalid",
            });
        }
        let receipt_sha256 = isolation_receipt_sha256(
            &request,
            prepared_revision,
            &resident_process_generation_sha256,
            &resident_store_generation_sha256,
        );
        Ok(Self {
            request,
            prepared_revision,
            resident_process_generation_sha256,
            resident_store_generation_sha256,
            receipt_sha256,
        })
    }

    // Returns the exact transaction request.
    pub const fn request(&self) -> &PlacementBenchmarkIsolationRequest {
        &self.request
    }

    // Returns the aggregate revision captured before benchmark mutation.
    pub const fn prepared_revision(&self) -> u64 {
        self.prepared_revision
    }

    // Returns the resident native process generation captured before isolation.
    pub const fn resident_process_generation_sha256(&self) -> &Sha256Digest {
        &self.resident_process_generation_sha256
    }

    // Returns the resident prefix-store generation captured before isolation.
    pub const fn resident_store_generation_sha256(&self) -> &Sha256Digest {
        &self.resident_store_generation_sha256
    }

    // Returns the unambiguous resident snapshot identity.
    pub const fn receipt_sha256(&self) -> &Sha256Digest {
        &self.receipt_sha256
    }
}

// Proves the original store and a fresh resident process are active after cleanup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlacementBenchmarkRestorationReceipt {
    isolation: PlacementBenchmarkIsolationReceipt,
    previous_revision: u64,
    next_revision: u64,
    restored_process_generation_sha256: Sha256Digest,
    restored_at: UnixMilliseconds,
    receipt_sha256: Sha256Digest,
}

impl PlacementBenchmarkRestorationReceipt {
    // Creates one terminal restoration receipt only after the original store is running again.
    pub fn new(
        isolation: PlacementBenchmarkIsolationReceipt,
        previous_revision: u64,
        next_revision: u64,
        restored_process_generation_sha256: Sha256Digest,
        restored_at: UnixMilliseconds,
    ) -> Result<Self, PlacementError> {
        if previous_revision < isolation.prepared_revision()
            || next_revision <= previous_revision
            || restored_at.value() == 0
        {
            return Err(PlacementError::InvalidRequest {
                reason: "benchmark restoration receipt is invalid",
            });
        }
        let receipt_sha256 = restoration_receipt_sha256(
            &isolation,
            previous_revision,
            next_revision,
            &restored_process_generation_sha256,
            restored_at,
        );
        Ok(Self {
            isolation,
            previous_revision,
            next_revision,
            restored_process_generation_sha256,
            restored_at,
            receipt_sha256,
        })
    }

    // Returns the original resident snapshot restored by this receipt.
    pub const fn isolation(&self) -> &PlacementBenchmarkIsolationReceipt {
        &self.isolation
    }

    // Returns the aggregate revision immediately before terminal restoration.
    pub const fn previous_revision(&self) -> u64 {
        self.previous_revision
    }

    // Returns the exact running aggregate revision after restoration.
    pub const fn next_revision(&self) -> u64 {
        self.next_revision
    }

    // Returns the fresh process generation serving the restored resident store.
    pub const fn restored_process_generation_sha256(&self) -> &Sha256Digest {
        &self.restored_process_generation_sha256
    }

    // Returns when PlacementManager completed terminal restoration.
    pub const fn restored_at(&self) -> UnixMilliseconds {
        self.restored_at
    }

    // Returns the complete unambiguous restoration identity.
    pub const fn receipt_sha256(&self) -> &Sha256Digest {
        &self.receipt_sha256
    }
}

impl PlacementBenchmarkGenerations {
    // Creates one native process/store observation without deriving either identity from revision.
    pub const fn new(
        process_generation_sha256: Sha256Digest,
        store_generation_sha256: Sha256Digest,
    ) -> Self {
        Self {
            process_generation_sha256,
            store_generation_sha256,
        }
    }

    // Returns the native PID-reuse-safe or launchd process generation.
    pub const fn process_generation_sha256(&self) -> &Sha256Digest {
        &self.process_generation_sha256
    }

    // Returns the exact prefix-store generation marker.
    pub const fn store_generation_sha256(&self) -> &Sha256Digest {
        &self.store_generation_sha256
    }
}

// Commands one idempotent fresh process/store generation for a benchmark context boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlacementBenchmarkResetRequest {
    reset_id: Sha256Digest,
    placement_group_id: PlacementGroupId,
    expected_revision: u64,
    context: String,
    context_index: u32,
    context_count: u32,
}

impl PlacementBenchmarkResetRequest {
    // Creates one ordered reset command without treating its context label as isolation proof.
    pub fn new(
        reset_id: Sha256Digest,
        placement_group_id: PlacementGroupId,
        expected_revision: u64,
        context: &str,
        context_index: u32,
        context_count: u32,
    ) -> Result<Self, PlacementError> {
        if expected_revision == 0
            || !valid_context(context)
            || context_index == 0
            || context_count == 0
            || context_index > context_count
        {
            return Err(PlacementError::InvalidRequest {
                reason: "benchmark reset identity or ordering is invalid",
            });
        }
        Ok(Self {
            reset_id,
            placement_group_id,
            expected_revision,
            context: context.to_string(),
            context_index,
            context_count,
        })
    }

    // Returns the idempotency identity derived by the BenchmarkManager adapter.
    pub const fn reset_id(&self) -> &Sha256Digest {
        &self.reset_id
    }

    // Returns the exact placement group to reset.
    pub const fn placement_group_id(&self) -> &PlacementGroupId {
        &self.placement_group_id
    }

    // Returns the aggregate revision observed before the first reset attempt.
    pub const fn expected_revision(&self) -> u64 {
        self.expected_revision
    }

    // Returns the schema-owned context group label.
    pub fn context(&self) -> &str {
        &self.context
    }

    // Returns the one-based context group index.
    pub const fn context_index(&self) -> u32 {
        self.context_index
    }

    // Returns the complete selected context group count.
    pub const fn context_count(&self) -> u32 {
        self.context_count
    }

    // Requires a durable replay receipt to belong to this logical reset boundary.
    pub(crate) fn matches_receipt(&self, receipt: &PlacementBenchmarkResetReceipt) -> bool {
        self.reset_id() == receipt.reset_id()
            && self.placement_group_id() == receipt.placement_group_id()
            && self.expected_revision() == receipt.expected_revision()
            && self.context() == receipt.context()
            && self.context_index() == receipt.context_index()
            && self.context_count() == receipt.context_count()
    }
}

// Proves one exact aggregate restart, empty store generation, and native process generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlacementBenchmarkResetReceipt {
    reset_id: Sha256Digest,
    placement_group_id: PlacementGroupId,
    context: String,
    context_index: u32,
    context_count: u32,
    expected_revision: u64,
    previous_revision: u64,
    next_revision: u64,
    store_generation_sha256: Sha256Digest,
    process_generation_sha256: Sha256Digest,
    reset_at: UnixMilliseconds,
    receipt_sha256: Sha256Digest,
}

impl PlacementBenchmarkResetReceipt {
    // Creates one complete receipt only after the fresh group is running and observable.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request: &PlacementBenchmarkResetRequest,
        previous_revision: u64,
        next_revision: u64,
        store_generation_sha256: Sha256Digest,
        process_generation_sha256: Sha256Digest,
        reset_at: UnixMilliseconds,
    ) -> Result<Self, PlacementError> {
        if previous_revision != request.expected_revision()
            || next_revision <= previous_revision
            || reset_at.value() == 0
        {
            return Err(PlacementError::InvalidRequest {
                reason: "benchmark reset receipt revisions or time are invalid",
            });
        }
        let receipt_sha256 = receipt_sha256(
            request,
            previous_revision,
            next_revision,
            &store_generation_sha256,
            &process_generation_sha256,
            reset_at,
        );
        Ok(Self {
            reset_id: request.reset_id().clone(),
            placement_group_id: request.placement_group_id().clone(),
            context: request.context().to_string(),
            context_index: request.context_index(),
            context_count: request.context_count(),
            expected_revision: request.expected_revision(),
            previous_revision,
            next_revision,
            store_generation_sha256,
            process_generation_sha256,
            reset_at,
            receipt_sha256,
        })
    }

    // Returns the idempotent reset identity.
    pub const fn reset_id(&self) -> &Sha256Digest {
        &self.reset_id
    }

    // Returns the exact placement group reset by PlacementManager.
    pub const fn placement_group_id(&self) -> &PlacementGroupId {
        &self.placement_group_id
    }

    // Returns the schema-owned context group label.
    pub fn context(&self) -> &str {
        &self.context
    }

    // Returns the one-based context group index.
    pub const fn context_index(&self) -> u32 {
        self.context_index
    }

    // Returns the complete selected context group count.
    pub const fn context_count(&self) -> u32 {
        self.context_count
    }

    // Returns the caller's optimistic aggregate revision.
    pub const fn expected_revision(&self) -> u64 {
        self.expected_revision
    }

    // Returns the exact running aggregate revision before reset.
    pub const fn previous_revision(&self) -> u64 {
        self.previous_revision
    }

    // Returns the exact running aggregate revision after reset.
    pub const fn next_revision(&self) -> u64 {
        self.next_revision
    }

    // Returns the independently created empty prefix-store generation.
    pub const fn store_generation_sha256(&self) -> &Sha256Digest {
        &self.store_generation_sha256
    }

    // Returns the native PID-reuse-safe or launchd process generation.
    pub const fn process_generation_sha256(&self) -> &Sha256Digest {
        &self.process_generation_sha256
    }

    // Returns when PlacementManager completed the exact reset.
    pub const fn reset_at(&self) -> UnixMilliseconds {
        self.reset_at
    }

    // Returns the complete unambiguous receipt identity.
    pub const fn receipt_sha256(&self) -> &Sha256Digest {
        &self.receipt_sha256
    }
}

// Owns durable reset replay plus platform-native prefix-store and process observations.
pub trait PlacementBenchmarkResetProvider: Send + Sync {
    // Captures or replays the exact resident process/store identity before any benchmark reset.
    fn prepare_isolation(
        &self,
        _request: &PlacementBenchmarkIsolationRequest,
        _running: &VersionedPlacementRecord,
    ) -> Result<PlacementBenchmarkIsolationReceipt, PlacementError> {
        Err(PlacementError::ExecutionUnavailable)
    }

    // Returns the durable resident snapshot for one active or completed transaction.
    fn isolation_receipt(
        &self,
        _request: &PlacementBenchmarkIsolationRequest,
    ) -> Result<Option<PlacementBenchmarkIsolationReceipt>, PlacementError> {
        Err(PlacementError::ExecutionUnavailable)
    }

    // Returns the sole active resident snapshot for one placement group.
    fn active_isolation(
        &self,
        _placement_group_id: &PlacementGroupId,
    ) -> Result<Option<PlacementBenchmarkIsolationReceipt>, PlacementError> {
        Err(PlacementError::ExecutionUnavailable)
    }

    // Returns a previously committed terminal restoration for idempotent restart replay.
    fn restoration_receipt(
        &self,
        _request: &PlacementBenchmarkIsolationRequest,
    ) -> Result<Option<PlacementBenchmarkRestorationReceipt>, PlacementError> {
        Err(PlacementError::ExecutionUnavailable)
    }

    // Returns a previously committed receipt for one idempotency identity.
    fn receipt(
        &self,
        reset_id: &Sha256Digest,
    ) -> Result<Option<PlacementBenchmarkResetReceipt>, PlacementError>;

    // Observes the running group's exact current process and store generations before reset.
    fn generations(
        &self,
        request: &PlacementBenchmarkResetRequest,
        running: &VersionedPlacementRecord,
    ) -> Result<PlacementBenchmarkGenerations, PlacementError>;

    // Replaces the stopped group's prefix store with one independently generated empty store.
    fn reset_store(
        &self,
        request: &PlacementBenchmarkResetRequest,
        stopped: &VersionedPlacementRecord,
    ) -> Result<Sha256Digest, PlacementError>;

    // Observes the exact fresh native process generation after Placement readiness succeeds.
    fn process_generation(
        &self,
        request: &PlacementBenchmarkResetRequest,
        running: &VersionedPlacementRecord,
    ) -> Result<Sha256Digest, PlacementError>;

    // Commits one complete receipt atomically or returns the byte-identical prior receipt.
    fn commit(
        &self,
        receipt: PlacementBenchmarkResetReceipt,
    ) -> Result<PlacementBenchmarkResetReceipt, PlacementError>;

    // Restores the original resident store while the complete placement group is stopped.
    fn restore_store(
        &self,
        _request: &PlacementBenchmarkIsolationRequest,
        _stopped: &VersionedPlacementRecord,
    ) -> Result<Sha256Digest, PlacementError> {
        Err(PlacementError::ExecutionUnavailable)
    }

    // Observes the fresh resident process after the original store has restarted.
    fn restored_process_generation(
        &self,
        _request: &PlacementBenchmarkIsolationRequest,
        _running: &VersionedPlacementRecord,
    ) -> Result<Sha256Digest, PlacementError> {
        Err(PlacementError::ExecutionUnavailable)
    }

    // Commits terminal restoration atomically or returns the byte-identical prior receipt.
    fn commit_restoration(
        &self,
        _receipt: PlacementBenchmarkRestorationReceipt,
    ) -> Result<PlacementBenchmarkRestorationReceipt, PlacementError> {
        Err(PlacementError::ExecutionUnavailable)
    }
}

// Hashes one exact original resident snapshot with length framing for every field.
fn isolation_receipt_sha256(
    request: &PlacementBenchmarkIsolationRequest,
    prepared_revision: u64,
    resident_process_generation_sha256: &Sha256Digest,
    resident_store_generation_sha256: &Sha256Digest,
) -> Sha256Digest {
    let mut digest = Sha256::new();
    for value in [
        "li-placement-benchmark-isolation-v1".to_string(),
        request.isolation_id().as_str().to_string(),
        request.placement_group_id().as_str().to_string(),
        prepared_revision.to_string(),
        resident_process_generation_sha256.as_str().to_string(),
        resident_store_generation_sha256.as_str().to_string(),
    ] {
        digest.update(value.len().to_string().as_bytes());
        digest.update(b":");
        digest.update(value.as_bytes());
    }
    Sha256Digest::parse(&format!("{:x}", digest.finalize())).expect("SHA-256 is canonical")
}

// Hashes one terminal restoration receipt with the original snapshot identity.
fn restoration_receipt_sha256(
    isolation: &PlacementBenchmarkIsolationReceipt,
    previous_revision: u64,
    next_revision: u64,
    restored_process_generation_sha256: &Sha256Digest,
    restored_at: UnixMilliseconds,
) -> Sha256Digest {
    let mut digest = Sha256::new();
    for value in [
        "li-placement-benchmark-restoration-v1".to_string(),
        isolation.receipt_sha256().as_str().to_string(),
        previous_revision.to_string(),
        next_revision.to_string(),
        restored_process_generation_sha256.as_str().to_string(),
        restored_at.value().to_string(),
    ] {
        digest.update(value.len().to_string().as_bytes());
        digest.update(b":");
        digest.update(value.as_bytes());
    }
    Sha256Digest::parse(&format!("{:x}", digest.finalize())).expect("SHA-256 is canonical")
}

// Adds one unambiguous UTF-8 field to a generation or receipt digest.
fn framed_digest_field(digest: &mut Sha256, value: &str) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value.as_bytes());
}

// Hashes one exact reset receipt with length framing for every field.
fn receipt_sha256(
    request: &PlacementBenchmarkResetRequest,
    previous_revision: u64,
    next_revision: u64,
    store_generation_sha256: &Sha256Digest,
    process_generation_sha256: &Sha256Digest,
    reset_at: UnixMilliseconds,
) -> Sha256Digest {
    let mut digest = Sha256::new();
    for field in [
        "li-placement-benchmark-reset-v1".to_string(),
        request.reset_id().as_str().to_string(),
        request.placement_group_id().as_str().to_string(),
        request.context().to_string(),
        request.context_index().to_string(),
        request.context_count().to_string(),
        request.expected_revision().to_string(),
        previous_revision.to_string(),
        next_revision.to_string(),
        store_generation_sha256.as_str().to_string(),
        process_generation_sha256.as_str().to_string(),
        reset_at.value().to_string(),
    ] {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field.as_bytes());
    }
    Sha256Digest::parse(&format!("{:x}", digest.finalize()))
        .expect("SHA-256 formatting is canonical")
}

// Accepts only one bounded schema-owned benchmark context label.
fn valid_context(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}
