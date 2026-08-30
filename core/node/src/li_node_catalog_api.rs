// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashSet;
use std::error::Error;
use std::fmt;

use li_core_interface::{
    EvidenceLabel, LogicalModelName, NodeId, RuntimeCandidateId, Sha256Digest, TargetId,
    TechnicalName,
};

const MAXIMUM_CATALOG_SOURCE_BYTES: usize = 2_048;
const MAXIMUM_CATALOG_TEXT_BYTES: usize = 2_048;
const MAXIMUM_CATALOG_AUTHORS: usize = 64;
const MAXIMUM_CATALOG_ENTRIES: usize = 4_096;

// Selects whether a catalog listing returns only active releases or every active version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeCatalogVersionSelection {
    Latest,
    All,
}

// Selects whether a catalog listing is restricted to the local node's observed hardware.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeCatalogTargetSelection {
    Compatible,
    All,
}

// Selects ordinary verified-cache behavior or a strict signed refresh.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeCatalogRefreshPolicy {
    Cached,
    Refresh,
}

// Carries one closed catalog query without granting callers an alternate unsigned source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeCatalogListRequest {
    catalog_source: Option<String>,
    logical_model: Option<LogicalModelName>,
    versions: NodeCatalogVersionSelection,
    targets: NodeCatalogTargetSelection,
    refresh: NodeCatalogRefreshPolicy,
}

impl NodeCatalogListRequest {
    // Creates one validated query whose optional source may only assert configured identity.
    pub fn new(
        catalog_source: Option<String>,
        logical_model: Option<LogicalModelName>,
        versions: NodeCatalogVersionSelection,
        targets: NodeCatalogTargetSelection,
        refresh: NodeCatalogRefreshPolicy,
    ) -> Result<Self, NodeCatalogApiError> {
        Ok(Self {
            catalog_source: catalog_source.map(bounded_catalog_source).transpose()?,
            logical_model,
            versions,
            targets,
            refresh,
        })
    }

    // Returns the exact configured-source assertion when the caller supplied one.
    pub fn catalog_source(&self) -> Option<&str> {
        self.catalog_source.as_deref()
    }

    // Returns the optional logical-model filter.
    pub const fn logical_model(&self) -> Option<&LogicalModelName> {
        self.logical_model.as_ref()
    }

    // Returns the explicit version selection.
    pub const fn versions(&self) -> NodeCatalogVersionSelection {
        self.versions
    }

    // Returns the explicit hardware-target selection.
    pub const fn targets(&self) -> NodeCatalogTargetSelection {
        self.targets
    }

    // Returns the explicit signed-catalog freshness policy.
    pub const fn refresh(&self) -> NodeCatalogRefreshPolicy {
        self.refresh
    }
}

// Identifies one structured catalog author without flattening account type or numeric identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeCatalogAuthorKind {
    User,
    Organization,
}

// Preserves one ordered structured author from signed catalog publication metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeCatalogAuthor {
    login: String,
    numeric_id: u64,
    kind: NodeCatalogAuthorKind,
}

impl NodeCatalogAuthor {
    // Creates one bounded author identity suitable for private transport publication.
    pub fn new(
        login: String,
        numeric_id: u64,
        kind: NodeCatalogAuthorKind,
    ) -> Result<Self, NodeCatalogApiError> {
        if numeric_id == 0 || !is_bounded_text(&login, 255) {
            return Err(NodeCatalogApiError::InvalidResponse);
        }
        Ok(Self {
            login,
            numeric_id,
            kind,
        })
    }

    // Returns the exact published account login.
    pub fn login(&self) -> &str {
        &self.login
    }

    // Returns the immutable numeric account identity.
    pub const fn numeric_id(&self) -> u64 {
        self.numeric_id
    }

    // Returns whether this author is a user or organization.
    pub const fn kind(&self) -> NodeCatalogAuthorKind {
        self.kind
    }
}

// Preserves user-relevant identity and signed qualification fields for one active release.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeCatalogEntry {
    logical_model: LogicalModelName,
    target_id: TargetId,
    candidate_id: RuntimeCandidateId,
    version: String,
    runtime_source: String,
    engine: TechnicalName,
    model_uri: String,
    authors: Vec<NodeCatalogAuthor>,
    license: String,
    evidence_label: EvidenceLabel,
    verification_method: String,
    benchmark_score_bits: Option<u64>,
    recommended: bool,
}

impl NodeCatalogEntry {
    // Creates one bounded signed release projection without reinterpreting qualification.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        logical_model: LogicalModelName,
        target_id: TargetId,
        candidate_id: RuntimeCandidateId,
        version: String,
        runtime_source: String,
        engine: TechnicalName,
        model_uri: String,
        authors: Vec<NodeCatalogAuthor>,
        license: String,
        evidence_label: EvidenceLabel,
        verification_method: String,
        benchmark_score: Option<f64>,
        recommended: bool,
    ) -> Result<Self, NodeCatalogApiError> {
        if !is_bounded_text(&version, 128)
            || !is_bounded_text(&runtime_source, MAXIMUM_CATALOG_TEXT_BYTES)
            || !is_bounded_text(&model_uri, MAXIMUM_CATALOG_TEXT_BYTES)
            || authors.is_empty()
            || authors.len() > MAXIMUM_CATALOG_AUTHORS
            || !is_bounded_text(&license, 128)
            || !is_bounded_text(&verification_method, 128)
            || benchmark_score.is_some_and(|score| !score.is_finite() || score <= 0.0)
        {
            return Err(NodeCatalogApiError::InvalidResponse);
        }
        Ok(Self {
            logical_model,
            target_id,
            candidate_id,
            version,
            runtime_source,
            engine,
            model_uri,
            authors,
            license,
            evidence_label,
            verification_method,
            benchmark_score_bits: benchmark_score.map(f64::to_bits),
            recommended,
        })
    }

    // Returns the logical model exposed to users.
    pub const fn logical_model(&self) -> &LogicalModelName {
        &self.logical_model
    }

    // Returns the exact signed hardware-target identity.
    pub const fn target_id(&self) -> &TargetId {
        &self.target_id
    }

    // Returns the immutable runtime-candidate identity.
    pub const fn candidate_id(&self) -> &RuntimeCandidateId {
        &self.candidate_id
    }

    // Returns the exact published runtime version.
    pub fn version(&self) -> &str {
        &self.version
    }

    // Returns the immutable signed runtime source.
    pub fn runtime_source(&self) -> &str {
        &self.runtime_source
    }

    // Returns the Engine name projected from the runtime manifest.
    pub const fn engine(&self) -> &TechnicalName {
        &self.engine
    }

    // Returns the primary model artifact URI.
    pub fn model_uri(&self) -> &str {
        &self.model_uri
    }

    // Returns the ordered structured publication authors.
    pub fn authors(&self) -> &[NodeCatalogAuthor] {
        &self.authors
    }

    // Returns the SPDX publication license.
    pub fn license(&self) -> &str {
        &self.license
    }

    // Returns the descriptive evidence label without turning it into an admission gate.
    pub const fn evidence_label(&self) -> EvidenceLabel {
        self.evidence_label
    }

    // Returns the signed qualification method.
    pub fn verification_method(&self) -> &str {
        &self.verification_method
    }

    // Returns the positive finite benchmark score when the signed release carries one.
    pub fn benchmark_score(&self) -> Option<f64> {
        self.benchmark_score_bits.map(f64::from_bits)
    }

    // Returns whether this exact release is the active recommendation.
    pub const fn is_recommended(&self) -> bool {
        self.recommended
    }
}

// Carries the exact signed catalog and revocation identities behind one listing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeCatalogSnapshot {
    source: String,
    catalog_sha256: Sha256Digest,
    revocations_sha256: Sha256Digest,
    revocation_sequence: u64,
    verified_at_unix: u64,
    stale: bool,
}

impl NodeCatalogSnapshot {
    // Creates one bounded verified snapshot projection.
    pub fn new(
        source: String,
        catalog_sha256: Sha256Digest,
        revocations_sha256: Sha256Digest,
        revocation_sequence: u64,
        verified_at_unix: u64,
        stale: bool,
    ) -> Result<Self, NodeCatalogApiError> {
        Ok(Self {
            source: bounded_catalog_source(source)
                .map_err(|_| NodeCatalogApiError::InvalidResponse)?,
            catalog_sha256,
            revocations_sha256,
            revocation_sequence,
            verified_at_unix,
            stale,
        })
    }

    // Returns the exact configured signed-catalog source.
    pub fn source(&self) -> &str {
        &self.source
    }

    // Returns the SHA-256 of the exact verified catalog bytes.
    pub const fn catalog_sha256(&self) -> &Sha256Digest {
        &self.catalog_sha256
    }

    // Returns the SHA-256 of the exact verified revocation-ledger bytes.
    pub const fn revocations_sha256(&self) -> &Sha256Digest {
        &self.revocations_sha256
    }

    // Returns the monotonic verified revocation-ledger sequence.
    pub const fn revocation_sequence(&self) -> u64 {
        self.revocation_sequence
    }

    // Returns when the catalog and revocation ledger were verified together.
    pub const fn verified_at_unix(&self) -> u64 {
        self.verified_at_unix
    }

    // Returns whether ordinary loading reused an expired verified cache after network failure.
    pub const fn is_stale(&self) -> bool {
        self.stale
    }
}

// Carries one verified snapshot and its bounded ordered active releases.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeCatalogListing {
    snapshot: NodeCatalogSnapshot,
    entries: Vec<NodeCatalogEntry>,
}

impl NodeCatalogListing {
    // Creates one bounded listing and rejects duplicate exact release identities.
    pub fn new(
        snapshot: NodeCatalogSnapshot,
        entries: Vec<NodeCatalogEntry>,
    ) -> Result<Self, NodeCatalogApiError> {
        if entries.len() > MAXIMUM_CATALOG_ENTRIES {
            return Err(NodeCatalogApiError::InvalidResponse);
        }
        let mut identities = HashSet::with_capacity(entries.len());
        for entry in &entries {
            let identity = (
                entry.logical_model().as_str(),
                entry.target_id().as_str(),
                entry.candidate_id().as_str(),
                entry.version(),
            );
            if !identities.insert(identity) {
                return Err(NodeCatalogApiError::InvalidResponse);
            }
        }
        Ok(Self { snapshot, entries })
    }

    // Returns the signed snapshot identity shared by every entry.
    pub const fn snapshot(&self) -> &NodeCatalogSnapshot {
        &self.snapshot
    }

    // Returns the ordered active releases.
    pub fn entries(&self) -> &[NodeCatalogEntry] {
        &self.entries
    }
}

// Describes one compatible signed catalog release without copying catalog documents into Node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeCatalogTarget {
    logical_model: LogicalModelName,
    target_id: TargetId,
    candidate_id: RuntimeCandidateId,
    recommended: bool,
}

impl NodeCatalogTarget {
    // Creates one exact compatible target projection from already-validated catalog identities.
    pub const fn new(
        logical_model: LogicalModelName,
        target_id: TargetId,
        candidate_id: RuntimeCandidateId,
        recommended: bool,
    ) -> Self {
        Self {
            logical_model,
            target_id,
            candidate_id,
            recommended,
        }
    }

    // Returns the logical model exposed by this catalog release.
    pub const fn logical_model(&self) -> &LogicalModelName {
        &self.logical_model
    }

    // Returns the exact hardware-target identity matched by RuntimeManager.
    pub const fn target_id(&self) -> &TargetId {
        &self.target_id
    }

    // Returns the immutable runtime-candidate identity.
    pub const fn candidate_id(&self) -> &RuntimeCandidateId {
        &self.candidate_id
    }

    // Returns whether the signed catalog recommends this release.
    pub const fn is_recommended(&self) -> bool {
        self.recommended
    }
}

// Names stable catalog-projection failures without importing RuntimeManager internals.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeCatalogApiError {
    InvalidRequest,
    Unavailable,
    InvalidResponse,
}

impl fmt::Display for NodeCatalogApiError {
    // Presents fixed catalog language without exposing a source, catalog, or hardware document.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest => formatter.write_str("node catalog request is invalid"),
            Self::Unavailable => formatter.write_str("node catalog projection is unavailable"),
            Self::InvalidResponse => {
                formatter.write_str("node catalog projection returned invalid state")
            }
        }
    }
}

impl Error for NodeCatalogApiError {}

// Isolates NodeManager orchestration over hardware and RuntimeManager catalog judgment.
pub trait NodeCatalogApiPort: Send + Sync {
    // Returns one verified signed listing for the local node and exact closed query.
    fn list(
        &self,
        request: &NodeCatalogListRequest,
    ) -> Result<NodeCatalogListing, NodeCatalogApiError>;

    // Returns compatible signed targets for one exact node and configured catalog source.
    fn compatible_targets(
        &self,
        node_id: &NodeId,
        catalog_source: &str,
    ) -> Result<Vec<NodeCatalogTarget>, NodeCatalogApiError>;
}

// Validates one catalog source at the Node private boundary without interpreting its location.
pub(crate) fn bounded_catalog_source(value: String) -> Result<String, NodeCatalogApiError> {
    if !is_bounded_text(&value, MAXIMUM_CATALOG_SOURCE_BYTES) {
        return Err(NodeCatalogApiError::InvalidRequest);
    }
    Ok(value)
}

// Validates one manager-owned compatible-target collection before transport publication.
pub(crate) fn bounded_catalog_targets(
    targets: Vec<NodeCatalogTarget>,
) -> Result<Vec<NodeCatalogTarget>, NodeCatalogApiError> {
    if targets.len() > MAXIMUM_CATALOG_ENTRIES {
        return Err(NodeCatalogApiError::InvalidResponse);
    }
    Ok(targets)
}

// Returns whether one required text value is nonempty, bounded, and free of control bytes.
fn is_bounded_text(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty() && value.len() <= maximum_bytes && !value.chars().any(char::is_control)
}
