// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::sync::Arc;

use li_core_interface::{LogicalModelName, OperationId, Sha256Digest};

// Names one local Let's Infer storage class without exposing platform paths.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum NodeStorageCategory {
    Models,
    Runtimes,
    Caches,
    Benchmarks,
    Engines,
    Core,
    State,
    Configuration,
    Logs,
}

impl NodeStorageCategory {
    // Parses one closed private-wire or CLI category name.
    pub fn parse(value: &str) -> Result<Self, NodeStorageError> {
        match value {
            "models" => Ok(Self::Models),
            "runtimes" => Ok(Self::Runtimes),
            "caches" => Ok(Self::Caches),
            "benchmarks" => Ok(Self::Benchmarks),
            "engines" => Ok(Self::Engines),
            "core" => Ok(Self::Core),
            "state" => Ok(Self::State),
            "configuration" => Ok(Self::Configuration),
            "logs" => Ok(Self::Logs),
            _ => Err(NodeStorageError::InvalidRequest),
        }
    }

    // Returns the stable private-wire and CLI name for one category.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Models => "models",
            Self::Runtimes => "runtimes",
            Self::Caches => "caches",
            Self::Benchmarks => "benchmarks",
            Self::Engines => "engines",
            Self::Core => "core",
            Self::State => "state",
            Self::Configuration => "configuration",
            Self::Logs => "logs",
        }
    }

    // Returns whether reviewed inactive data in this category may be reclaimed.
    pub const fn is_reclaimable(self) -> bool {
        matches!(self, Self::Models | Self::Caches | Self::Benchmarks)
    }
}

// Stores measured bytes and file count for one storage class.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeStorageUsage {
    category: NodeStorageCategory,
    allocated_bytes: u64,
    logical_bytes: u64,
    files: u64,
    reclaimable_bytes: u64,
}

impl NodeStorageUsage {
    // Creates one category total only when reclaimability stays within allocation.
    pub fn new(
        category: NodeStorageCategory,
        allocated_bytes: u64,
        logical_bytes: u64,
        files: u64,
        reclaimable_bytes: u64,
    ) -> Result<Self, NodeStorageError> {
        if reclaimable_bytes > allocated_bytes
            || (!category.is_reclaimable() && reclaimable_bytes != 0)
        {
            return Err(NodeStorageError::InvalidProjection);
        }
        Ok(Self {
            category,
            allocated_bytes,
            logical_bytes,
            files,
            reclaimable_bytes,
        })
    }

    // Returns the category represented by this measured total.
    pub const fn category(&self) -> NodeStorageCategory {
        self.category
    }

    // Returns physical bytes allocated by this category.
    pub const fn allocated_bytes(&self) -> u64 {
        self.allocated_bytes
    }

    // Returns logical file bytes represented by this category.
    pub const fn logical_bytes(&self) -> u64 {
        self.logical_bytes
    }

    // Returns the number of non-directory entries represented by this category.
    pub const fn files(&self) -> u64 {
        self.files
    }

    // Returns reviewed physical bytes that may be reclaimed.
    pub const fn reclaimable_bytes(&self) -> u64 {
        self.reclaimable_bytes
    }
}

// Describes one exact reviewed cleanup target without publishing its absolute root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeStorageCandidate {
    category: NodeStorageCategory,
    relative_path: String,
    allocated_bytes: u64,
    reason: String,
    models: Vec<LogicalModelName>,
}

impl NodeStorageCandidate {
    // Creates one candidate with a canonical contained relative path and bounded reason.
    pub fn new(
        category: NodeStorageCategory,
        relative_path: impl Into<String>,
        allocated_bytes: u64,
        reason: impl Into<String>,
        mut models: Vec<LogicalModelName>,
    ) -> Result<Self, NodeStorageError> {
        let relative_path = relative_path.into();
        let reason = reason.into();
        if !category.is_reclaimable()
            || allocated_bytes == 0
            || !is_relative_storage_path(&relative_path)
            || reason.is_empty()
            || reason.len() > 512
        {
            return Err(NodeStorageError::InvalidProjection);
        }
        models.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        models.dedup();
        Ok(Self {
            category,
            relative_path,
            allocated_bytes,
            reason,
            models,
        })
    }

    // Returns the reclaimable category of this candidate.
    pub const fn category(&self) -> NodeStorageCategory {
        self.category
    }

    // Returns the normalized path relative to the private Let's Infer home.
    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }

    // Returns physical bytes represented by this exact target.
    pub const fn allocated_bytes(&self) -> u64 {
        self.allocated_bytes
    }

    // Returns the bounded user-safe reason this target is inactive.
    pub fn reason(&self) -> &str {
        &self.reason
    }

    // Returns models whose exact artifacts must be acquired again before startup.
    pub fn models(&self) -> &[LogicalModelName] {
        &self.models
    }
}

// Projects one complete measured local storage plan and its immutable review identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeStorageSnapshot {
    capacity_bytes: u64,
    available_bytes: u64,
    usage: Vec<NodeStorageUsage>,
    candidates: Vec<NodeStorageCandidate>,
    plan_digest: Sha256Digest,
}

impl NodeStorageSnapshot {
    // Creates one coherent snapshot with unique ordered categories and bounded totals.
    pub fn new(
        capacity_bytes: u64,
        available_bytes: u64,
        mut usage: Vec<NodeStorageUsage>,
        mut candidates: Vec<NodeStorageCandidate>,
        plan_digest: Sha256Digest,
    ) -> Result<Self, NodeStorageError> {
        if capacity_bytes == 0 || available_bytes > capacity_bytes {
            return Err(NodeStorageError::InvalidProjection);
        }
        usage.sort_by_key(NodeStorageUsage::category);
        if usage
            .windows(2)
            .any(|pair| pair[0].category() == pair[1].category())
        {
            return Err(NodeStorageError::InvalidProjection);
        }
        candidates.sort_by(|left, right| {
            left.category()
                .cmp(&right.category())
                .then_with(|| left.relative_path().cmp(right.relative_path()))
        });
        if candidates
            .windows(2)
            .any(|pair| pair[0].relative_path() == pair[1].relative_path())
        {
            return Err(NodeStorageError::InvalidProjection);
        }
        for category in [
            NodeStorageCategory::Models,
            NodeStorageCategory::Caches,
            NodeStorageCategory::Benchmarks,
        ] {
            let reported = usage
                .iter()
                .find(|value| value.category() == category)
                .map_or(0, NodeStorageUsage::reclaimable_bytes);
            let planned = candidates
                .iter()
                .filter(|value| value.category() == category)
                .try_fold(0_u64, |total, value| {
                    total.checked_add(value.allocated_bytes())
                })
                .ok_or(NodeStorageError::InvalidProjection)?;
            if reported != planned {
                return Err(NodeStorageError::InvalidProjection);
            }
        }
        Ok(Self {
            capacity_bytes,
            available_bytes,
            usage,
            candidates,
            plan_digest,
        })
    }

    // Returns the filesystem capacity containing the Let's Infer home.
    pub const fn capacity_bytes(&self) -> u64 {
        self.capacity_bytes
    }

    // Returns currently available bytes on the containing filesystem.
    pub const fn available_bytes(&self) -> u64 {
        self.available_bytes
    }

    // Returns every measured category in stable order.
    pub fn usage(&self) -> &[NodeStorageUsage] {
        &self.usage
    }

    // Returns exact reviewed inactive targets in stable order.
    pub fn candidates(&self) -> &[NodeStorageCandidate] {
        &self.candidates
    }

    // Returns the content identity that a cleanup request must preserve.
    pub const fn plan_digest(&self) -> &Sha256Digest {
        &self.plan_digest
    }
}

// Requests one cleanup against the exact plan already presented to the caller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeStorageCleanRequest {
    operation_id: OperationId,
    plan_digest: Sha256Digest,
    categories: BTreeSet<NodeStorageCategory>,
}

impl NodeStorageCleanRequest {
    // Creates one cleanup request only from nonempty reclaimable categories.
    pub fn new(
        operation_id: OperationId,
        plan_digest: Sha256Digest,
        categories: impl IntoIterator<Item = NodeStorageCategory>,
    ) -> Result<Self, NodeStorageError> {
        let categories = categories.into_iter().collect::<BTreeSet<_>>();
        if categories.is_empty() || categories.iter().any(|value| !value.is_reclaimable()) {
            return Err(NodeStorageError::InvalidRequest);
        }
        Ok(Self {
            operation_id,
            plan_digest,
            categories,
        })
    }

    // Returns the idempotent cleanup operation identity.
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    // Returns the exact reviewed plan identity.
    pub const fn plan_digest(&self) -> &Sha256Digest {
        &self.plan_digest
    }

    // Returns the selected reclaimable categories.
    pub const fn categories(&self) -> &BTreeSet<NodeStorageCategory> {
        &self.categories
    }
}

// Returns one durable cleanup result without exposing removed absolute paths.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeStorageCleanReceipt {
    operation_id: OperationId,
    plan_digest: Sha256Digest,
    removed_targets: u64,
    reclaimed_bytes: u64,
    models_to_download: Vec<LogicalModelName>,
    replayed: bool,
}

impl NodeStorageCleanReceipt {
    // Creates one receipt bound to the request and a deduplicated model set.
    pub fn new(
        operation_id: OperationId,
        plan_digest: Sha256Digest,
        removed_targets: u64,
        reclaimed_bytes: u64,
        mut models_to_download: Vec<LogicalModelName>,
        replayed: bool,
    ) -> Result<Self, NodeStorageError> {
        if (removed_targets == 0) != (reclaimed_bytes == 0) {
            return Err(NodeStorageError::InvalidProjection);
        }
        models_to_download.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        models_to_download.dedup();
        Ok(Self {
            operation_id,
            plan_digest,
            removed_targets,
            reclaimed_bytes,
            models_to_download,
            replayed,
        })
    }

    // Returns the idempotent cleanup operation identity.
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    // Returns the plan identity actually applied by the provider.
    pub const fn plan_digest(&self) -> &Sha256Digest {
        &self.plan_digest
    }

    // Returns the number of exact inactive targets removed.
    pub const fn removed_targets(&self) -> u64 {
        self.removed_targets
    }

    // Returns physical bytes represented by the removed plan entries.
    pub const fn reclaimed_bytes(&self) -> u64 {
        self.reclaimed_bytes
    }

    // Returns models whose exact artifacts must be reacquired before start.
    pub fn models_to_download(&self) -> &[LogicalModelName] {
        &self.models_to_download
    }

    // Returns whether the provider replayed an already committed operation.
    pub const fn replayed(&self) -> bool {
        self.replayed
    }
}

// Supplies read-only local storage measurement without owning another manager's data.
pub trait NodeStorageObservationProvider: Send + Sync {
    // Measures one complete stable cleanup plan without mutating storage.
    fn snapshot(&self) -> Result<NodeStorageSnapshot, NodeStorageError>;
}

// Coordinates cleanup through the existing Runtime, Placement, and Benchmark owners.
pub trait NodeStorageCleanupPort: Send + Sync {
    // Applies one exact reviewed request through its owning managers or returns a durable replay.
    fn clean(
        &self,
        request: &NodeStorageCleanRequest,
    ) -> Result<NodeStorageCleanReceipt, NodeStorageError>;
}

// Defines the narrow Node private-API surface for local storage operations.
pub trait NodeStorageApiPort: Send + Sync {
    // Returns one exact storage snapshot for review.
    fn snapshot(&self) -> Result<NodeStorageSnapshot, NodeStorageError>;

    // Applies one content-bound cleanup through existing lifecycle owners.
    fn clean(
        &self,
        request: &NodeStorageCleanRequest,
    ) -> Result<NodeStorageCleanReceipt, NodeStorageError>;
}

// Owns NodeManager ordering around local storage review and cleanup.
pub struct NodeStorageCoordinator {
    observation: Arc<dyn NodeStorageObservationProvider>,
    cleanup: Arc<dyn NodeStorageCleanupPort>,
}

impl NodeStorageCoordinator {
    // Creates one coordinator from separate read-only observation and manager-owned cleanup ports.
    pub fn new(
        observation: Arc<dyn NodeStorageObservationProvider>,
        cleanup: Arc<dyn NodeStorageCleanupPort>,
    ) -> Self {
        Self {
            observation,
            cleanup,
        }
    }

    // Returns one provider-validated storage projection without hidden cleanup.
    pub fn snapshot(&self) -> Result<NodeStorageSnapshot, NodeStorageError> {
        self.observation.snapshot()
    }

    // Rechecks the plan identity before delegating one exact cleanup mutation.
    pub fn clean(
        &self,
        request: &NodeStorageCleanRequest,
    ) -> Result<NodeStorageCleanReceipt, NodeStorageError> {
        let current = self.observation.snapshot()?;
        if current.plan_digest() != request.plan_digest() {
            return Err(NodeStorageError::PlanChanged);
        }
        if request.categories().iter().any(|category| {
            !current
                .candidates()
                .iter()
                .any(|candidate| candidate.category() == *category)
        }) {
            return Err(NodeStorageError::InvalidRequest);
        }
        let receipt = self.cleanup.clean(request)?;
        if receipt.operation_id() != request.operation_id()
            || receipt.plan_digest() != request.plan_digest()
        {
            return Err(NodeStorageError::InvalidProjection);
        }
        Ok(receipt)
    }
}

impl NodeStorageApiPort for NodeStorageCoordinator {
    // Returns the current read-only observation through the coordinator contract.
    fn snapshot(&self) -> Result<NodeStorageSnapshot, NodeStorageError> {
        NodeStorageCoordinator::snapshot(self)
    }

    // Rechecks and applies one exact reviewed cleanup through manager-owned authorities.
    fn clean(
        &self,
        request: &NodeStorageCleanRequest,
    ) -> Result<NodeStorageCleanReceipt, NodeStorageError> {
        NodeStorageCoordinator::clean(self, request)
    }
}

// Describes a malformed request, changed plan, or redacted provider failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeStorageError {
    InvalidRequest,
    InvalidProjection,
    PlanChanged,
    ProviderUnavailable,
}

impl fmt::Display for NodeStorageError {
    // Presents one stable storage failure without filesystem or process diagnostics.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRequest => "storage cleanup request is invalid",
            Self::InvalidProjection => "storage projection is invalid",
            Self::PlanChanged => "storage cleanup plan changed after review",
            Self::ProviderUnavailable => "storage provider is unavailable",
        })
    }
}

impl Error for NodeStorageError {}

// Returns whether one public path remains a normalized relative child of the private home.
fn is_relative_storage_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 4096
        && !value.starts_with('/')
        && !value.ends_with('/')
        && value
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
}
