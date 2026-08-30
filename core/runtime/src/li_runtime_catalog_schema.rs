// SPDX-License-Identifier: AGPL-3.0-only

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashSet};

use li_core_interface::{
    ArtifactRevision, ByteCount, CpuArchitecture, HardwareObservation, LogicalModelName,
    MemoryTopology, NativeEngineKind, OperatingSystem, PlatformIdentity, RuntimeCandidateId,
    RuntimeSource, Sha256Digest, TargetId, TechnicalName,
};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use serde_json::{Map, Number, Value};

use super::li_runtime_catalog_provider::{
    canonical_json_bytes, sha256_digest, RuntimeCatalogAuthor, RuntimeCatalogAuthorKind,
    RuntimeCatalogEngineDistribution, RuntimeCatalogInterconnectKind, RuntimeCatalogListEntry,
    RuntimeCatalogPlacement, RuntimeCatalogTarget, CATALOG_SCHEMA_VERSION, MAXIMUM_CATALOG_BYTES,
    MAXIMUM_LEDGER_BYTES, RECOMMENDATION_POLICY, RECOMMENDATION_SUITE,
};
use crate::{RuntimeAcceleratorPartitioning, RuntimeError};

#[derive(Clone)]
struct ParsedRelease {
    authors: Vec<RuntimeCatalogAuthor>,
    license: String,
    source: RuntimeSource,
    engine: TechnicalName,
    engine_distribution: RuntimeCatalogEngineDistribution,
    model_uri: String,
    benchmark_score_bits: Option<u64>,
    provenance: Value,
    verification: Value,
    verification_method: String,
    consensus_sha256: Option<Sha256Digest>,
}

#[derive(Clone)]
struct ParsedCandidate {
    latest: String,
    releases: BTreeMap<String, ParsedRelease>,
}

#[derive(Clone)]
struct ParsedModelTarget {
    recommended: Option<(String, String)>,
    candidates: BTreeMap<String, ParsedCandidate>,
}

#[derive(Clone)]
struct ParsedModel {
    targets: BTreeMap<String, ParsedModelTarget>,
}

#[derive(Clone)]
pub(crate) struct ParsedCatalog {
    targets: BTreeMap<String, RuntimeCatalogTarget>,
    models: BTreeMap<String, ParsedModel>,
}

pub(crate) struct RevocationLedger {
    sequence: u64,
    entries: BTreeSet<(String, String)>,
}

impl RevocationLedger {
    // Returns the monotonic signed ledger sequence used to reject rollback.
    pub(crate) const fn sequence(&self) -> u64 {
        self.sequence
    }
}

pub(crate) struct ActiveCatalog {
    targets: BTreeMap<String, RuntimeCatalogTarget>,
    models: BTreeMap<String, ParsedModel>,
}

impl ActiveCatalog {
    // Lists active releases with deterministic model, target, candidate, and version order.
    pub(crate) fn entries(
        &self,
        requested_model: Option<&LogicalModelName>,
        include_versions: bool,
    ) -> Vec<RuntimeCatalogListEntry> {
        let mut result = Vec::new();
        for (model, model_record) in &self.models {
            if requested_model.is_some_and(|requested| requested.as_str() != model) {
                continue;
            }
            for (target_id, target_record) in &model_record.targets {
                for (candidate_id, candidate_record) in &target_record.candidates {
                    let versions = if include_versions {
                        sorted_versions(&candidate_record.releases)
                    } else {
                        vec![candidate_record.latest.clone()]
                    };
                    for version in versions {
                        if let Some(release) = candidate_record.releases.get(&version) {
                            result.push(list_entry(
                                model,
                                self.targets.get(target_id).expect("validated target"),
                                candidate_id,
                                &version,
                                release,
                                target_record.recommended.as_ref()
                                    == Some(&(candidate_id.clone(), version.clone())),
                            ));
                        }
                    }
                }
            }
        }
        result
    }

    // Returns latest explicit releases plus any distinct exact recommended release.
    pub(crate) fn selection_entries(
        &self,
        model: &LogicalModelName,
    ) -> Vec<RuntimeCatalogListEntry> {
        let Some(record) = self.models.get(model.as_str()) else {
            return Vec::new();
        };
        let mut result = Vec::new();
        for (target_id, target_record) in &record.targets {
            let target = self.targets.get(target_id).expect("validated target");
            if !target.is_core_platform() {
                continue;
            }
            for (candidate_id, candidate_record) in &target_record.candidates {
                if let Some(release) = candidate_record.releases.get(&candidate_record.latest) {
                    result.push(list_entry(
                        model.as_str(),
                        target,
                        candidate_id,
                        &candidate_record.latest,
                        release,
                        target_record.recommended.as_ref()
                            == Some(&(candidate_id.clone(), candidate_record.latest.clone())),
                    ));
                }
                if let Some((recommended_candidate, recommended_version)) =
                    &target_record.recommended
                {
                    if recommended_candidate == candidate_id
                        && recommended_version != &candidate_record.latest
                    {
                        if let Some(release) = candidate_record.releases.get(recommended_version) {
                            result.push(list_entry(
                                model.as_str(),
                                target,
                                candidate_id,
                                recommended_version,
                                release,
                                true,
                            ));
                        }
                    }
                }
            }
        }
        result
    }
}

// Parses and semantically validates one complete schema-7 catalog.
pub(crate) fn parse_catalog(bytes: &[u8]) -> Result<ParsedCatalog, RuntimeError> {
    if bytes.is_empty() || bytes.len() > MAXIMUM_CATALOG_BYTES as usize {
        return Err(RuntimeError::CatalogInvalid);
    }
    let value = parse_closed_json(bytes).map_err(|_| RuntimeError::CatalogInvalid)?;
    let root = object(&value).map_err(|_| RuntimeError::CatalogInvalid)?;
    require_fields(
        root,
        &[
            "models",
            "recommendation_policy",
            "schema_version",
            "targets",
        ],
    )?;
    if unsigned(root, "schema_version")? != CATALOG_SCHEMA_VERSION {
        return Err(RuntimeError::CatalogInvalid);
    }
    validate_recommendation_policy(
        root.get("recommendation_policy")
            .ok_or(RuntimeError::CatalogInvalid)?,
    )?;
    let target_values = object(root.get("targets").ok_or(RuntimeError::CatalogInvalid)?)?;
    if target_values.is_empty() {
        return Err(RuntimeError::CatalogInvalid);
    }
    let mut targets = BTreeMap::new();
    for (target_id, target_value) in target_values {
        if !is_safe_name(target_id) {
            return Err(RuntimeError::CatalogInvalid);
        }
        let target_record = object(target_value)?;
        require_fields(target_record, &["match"])?;
        let target = parse_target(
            target_id,
            target_record
                .get("match")
                .ok_or(RuntimeError::CatalogInvalid)?,
        )?;
        targets.insert(target_id.clone(), target);
    }
    let model_values = object(root.get("models").ok_or(RuntimeError::CatalogInvalid)?)?;
    let mut models = BTreeMap::new();
    for (model, model_value) in model_values {
        if !is_safe_name(model) || LogicalModelName::parse(model).is_err() {
            return Err(RuntimeError::CatalogInvalid);
        }
        let model_record = object(model_value)?;
        require_fields(model_record, &["targets"])?;
        let model_targets = object(
            model_record
                .get("targets")
                .ok_or(RuntimeError::CatalogInvalid)?,
        )?;
        if model_targets.is_empty() {
            return Err(RuntimeError::CatalogInvalid);
        }
        let mut parsed_targets = BTreeMap::new();
        for (target_id, target_value) in model_targets {
            if !targets.contains_key(target_id) {
                return Err(RuntimeError::CatalogInvalid);
            }
            parsed_targets.insert(
                target_id.clone(),
                parse_model_target(
                    model,
                    targets.get(target_id).expect("validated target"),
                    target_value,
                )?,
            );
        }
        models.insert(
            model.clone(),
            ParsedModel {
                targets: parsed_targets,
            },
        );
    }
    Ok(ParsedCatalog { targets, models })
}

// Validates the one supported recommendation policy without accepting aliases.
fn validate_recommendation_policy(value: &Value) -> Result<(), RuntimeError> {
    let policy = object(value)?;
    require_fields(
        policy,
        &["benchmark_suite", "cache", "id", "metric", "tie_breakers"],
    )?;
    let tie_breakers = array(
        policy
            .get("tie_breakers")
            .ok_or(RuntimeError::CatalogInvalid)?,
    )?;
    if string(policy, "id")? != RECOMMENDATION_POLICY
        || string(policy, "benchmark_suite")? != RECOMMENDATION_SUITE
        || string(policy, "metric")? != "aggregate_tps"
        || string(policy, "cache")? != "uncached"
        || tie_breakers.as_slice()
            != [
                Value::String("score".to_string()),
                Value::String("version".to_string()),
                Value::String("candidate".to_string()),
            ]
    {
        return Err(RuntimeError::CatalogInvalid);
    }
    Ok(())
}

// Parses one complete target contract and binds its canonical digest.
fn parse_target(target_id: &str, value: &Value) -> Result<RuntimeCatalogTarget, RuntimeError> {
    let root = object(value)?;
    require_fields(
        root,
        &["accelerator", "id", "memory", "placement", "platform"],
    )?;
    if string(root, "id")? != target_id || !is_platform(string(root, "platform")?) {
        return Err(RuntimeError::CatalogInvalid);
    }
    let (operating_system, architecture) = string(root, "platform")?
        .split_once('/')
        .ok_or(RuntimeError::CatalogInvalid)?;
    let accelerator = object(
        root.get("accelerator")
            .ok_or(RuntimeError::CatalogInvalid)?,
    )?;
    require_optional_fields(
        accelerator,
        &["architecture", "count", "partitioning", "vendor"],
        &["minimum_memory_gib"],
    )?;
    let vendor = string(accelerator, "vendor")?;
    let compute = string(accelerator, "architecture")?;
    if !is_safe_name(vendor) || !is_safe_name(compute) {
        return Err(RuntimeError::CatalogInvalid);
    }
    let count = positive(unsigned(accelerator, "count")?)?;
    let partitioning = match string(accelerator, "partitioning")? {
        "full-device" => RuntimeAcceleratorPartitioning::FullDevice,
        "mig" => RuntimeAcceleratorPartitioning::Mig,
        _ => return Err(RuntimeError::CatalogInvalid),
    };
    let minimum_accelerator_memory_gib = optional_positive(accelerator, "minimum_memory_gib")?;
    let memory = object(root.get("memory").ok_or(RuntimeError::CatalogInvalid)?)?;
    require_fields(memory, &["minimum_total_gib", "topology"])?;
    let memory_topology = match string(memory, "topology")? {
        "unified" => MemoryTopology::Unified,
        "discrete" => MemoryTopology::Discrete,
        _ => return Err(RuntimeError::CatalogInvalid),
    };
    let minimum_total_memory_gib = positive(unsigned(memory, "minimum_total_gib")?)?;
    let placement = parse_placement(root.get("placement").ok_or(RuntimeError::CatalogInvalid)?)?;
    Ok(RuntimeCatalogTarget {
        id: TargetId::parse(target_id).map_err(|_| RuntimeError::CatalogInvalid)?,
        operating_system: operating_system.to_string(),
        architecture: architecture.to_string(),
        accelerator_vendor: vendor.to_string(),
        compute_architecture: compute.to_string(),
        accelerator_count: count,
        accelerator_partitioning: partitioning,
        minimum_accelerator_memory_gib,
        memory_topology,
        minimum_total_memory_gib,
        placement,
        contract_sha256: sha256_digest(&canonical_json_bytes(value)?),
    })
}

// Parses placement requirements without turning them into host-observation policy.
fn parse_placement(value: &Value) -> Result<RuntimeCatalogPlacement, RuntimeError> {
    let placement = object(value)?;
    require_fields(placement, &["interconnect", "node_count", "strategy"])?;
    let parallel = match string(placement, "strategy")? {
        "single" => false,
        "parallel" => true,
        _ => return Err(RuntimeError::CatalogInvalid),
    };
    let node_count = bounded_u16(unsigned(placement, "node_count")?, 1, 64)?;
    if !parallel && node_count != 1 {
        return Err(RuntimeError::CatalogInvalid);
    }
    let interconnect = object(
        placement
            .get("interconnect")
            .ok_or(RuntimeError::CatalogInvalid)?,
    )?;
    require_fields(
        interconnect,
        &["kind", "minimum_mtu", "minimum_speed_mbps", "rdma_required"],
    )?;
    let kind = match string(interconnect, "kind")? {
        "any" => RuntimeCatalogInterconnectKind::Any,
        "connectx" => RuntimeCatalogInterconnectKind::Connectx,
        "ethernet" => RuntimeCatalogInterconnectKind::Ethernet,
        "wifi" => RuntimeCatalogInterconnectKind::Wifi,
        "other" => RuntimeCatalogInterconnectKind::Other,
        _ => return Err(RuntimeError::CatalogInvalid),
    };
    let rdma_required = boolean(interconnect, "rdma_required")?;
    let minimum_speed_mbps = unsigned(interconnect, "minimum_speed_mbps")?;
    let minimum_mtu = u32::try_from(unsigned(interconnect, "minimum_mtu")?)
        .map_err(|_| RuntimeError::CatalogInvalid)?;
    if !parallel
        && (kind != RuntimeCatalogInterconnectKind::Any
            || rdma_required
            || minimum_speed_mbps != 0
            || minimum_mtu != 0)
    {
        return Err(RuntimeError::CatalogInvalid);
    }
    Ok(RuntimeCatalogPlacement {
        parallel,
        node_count,
        interconnect: kind,
        rdma_required,
        minimum_speed_mbps,
        minimum_mtu,
    })
}

// Parses one model/target selection tree and validates every immutable release identity.
fn parse_model_target(
    model: &str,
    target: &RuntimeCatalogTarget,
    value: &Value,
) -> Result<ParsedModelTarget, RuntimeError> {
    let root = object(value)?;
    require_fields(root, &["candidates", "recommended"])?;
    let recommended = match root.get("recommended") {
        Some(Value::Null) => None,
        Some(value) => {
            let value = object(value)?;
            require_fields(value, &["candidate", "version"])?;
            let candidate = string(value, "candidate")?;
            let version = string(value, "version")?;
            if !is_safe_name(candidate) || !is_version(version) {
                return Err(RuntimeError::CatalogInvalid);
            }
            Some((candidate.to_string(), version.to_string()))
        }
        None => return Err(RuntimeError::CatalogInvalid),
    };
    let candidate_values = object(root.get("candidates").ok_or(RuntimeError::CatalogInvalid)?)?;
    if candidate_values.is_empty() {
        return Err(RuntimeError::CatalogInvalid);
    }
    let mut candidates = BTreeMap::new();
    for (candidate_id, candidate_value) in candidate_values {
        if !is_safe_name(candidate_id) || RuntimeCandidateId::parse(candidate_id).is_err() {
            return Err(RuntimeError::CatalogInvalid);
        }
        let record = object(candidate_value)?;
        require_fields(record, &["latest", "releases"])?;
        let latest = string(record, "latest")?;
        if !is_version(latest) {
            return Err(RuntimeError::CatalogInvalid);
        }
        let releases = object(record.get("releases").ok_or(RuntimeError::CatalogInvalid)?)?;
        if releases.is_empty() || !releases.contains_key(latest) {
            return Err(RuntimeError::CatalogInvalid);
        }
        let mut parsed_releases = BTreeMap::new();
        for (version, release) in releases {
            if !is_version(version) {
                return Err(RuntimeError::CatalogInvalid);
            }
            parsed_releases.insert(
                version.clone(),
                parse_release(model, target, candidate_id, version, release)?,
            );
        }
        candidates.insert(
            candidate_id.clone(),
            ParsedCandidate {
                latest: latest.to_string(),
                releases: parsed_releases,
            },
        );
    }
    if let Some((candidate, version)) = &recommended {
        let release = candidates
            .get(candidate)
            .and_then(|record| record.releases.get(version))
            .ok_or(RuntimeError::CatalogInvalid)?;
        if release.benchmark_score_bits.is_none() {
            return Err(RuntimeError::CatalogInvalid);
        }
    }
    Ok(ParsedModelTarget {
        recommended,
        candidates,
    })
}

// Parses one catalog release projection and its qualification metadata.
fn parse_release(
    _model: &str,
    target: &RuntimeCatalogTarget,
    candidate_id: &str,
    version: &str,
    value: &Value,
) -> Result<ParsedRelease, RuntimeError> {
    let root = object(value)?;
    require_fields(
        root,
        &[
            "authors",
            "benchmark",
            "engine",
            "engine_distribution",
            "license",
            "model_uri",
            "provenance",
            "source",
            "verification",
        ],
    )?;
    let authors = parse_authors(root.get("authors").ok_or(RuntimeError::CatalogInvalid)?)?;
    let license = string(root, "license")?;
    if !is_license(license) {
        return Err(RuntimeError::CatalogInvalid);
    }
    let source_value = string(root, "source")?;
    if !is_registry_source(source_value) {
        return Err(RuntimeError::CatalogInvalid);
    }
    let source = RuntimeSource::parse(source_value).map_err(|_| RuntimeError::CatalogInvalid)?;
    let engine_name = string(root, "engine")?;
    if !is_safe_name(engine_name) {
        return Err(RuntimeError::CatalogInvalid);
    }
    let engine = TechnicalName::parse(engine_name).map_err(|_| RuntimeError::CatalogInvalid)?;
    let engine_distribution = parse_engine_distribution(
        root.get("engine_distribution")
            .ok_or(RuntimeError::CatalogInvalid)?,
        &format!("{}/{}", target.operating_system, target.architecture),
    )?;
    let model_uri = string(root, "model_uri")?;
    let (owner, repository) = hugging_face_identity(model_uri)?;
    let expected_candidate = format!(
        "{}--{}--{}--{}",
        engine_name,
        owner.to_ascii_lowercase(),
        repository.to_ascii_lowercase(),
        target.id().as_str()
    );
    if candidate_id != expected_candidate {
        return Err(RuntimeError::CatalogInvalid);
    }
    let benchmark_score_bits =
        parse_benchmark(root.get("benchmark").ok_or(RuntimeError::CatalogInvalid)?)?;
    let provenance = root
        .get("provenance")
        .ok_or(RuntimeError::CatalogInvalid)?
        .clone();
    let verification = root
        .get("verification")
        .ok_or(RuntimeError::CatalogInvalid)?
        .clone();
    let (verification_method, consensus_sha256) = validate_qualification(
        candidate_id,
        version,
        benchmark_score_bits,
        &provenance,
        &verification,
        source.as_str(),
    )?;
    Ok(ParsedRelease {
        authors,
        license: license.to_string(),
        source,
        engine,
        engine_distribution,
        model_uri: model_uri.to_string(),
        benchmark_score_bits,
        provenance,
        verification,
        verification_method,
        consensus_sha256,
    })
}

// Parses an ordered, unique, structured publication-author array.
fn parse_authors(value: &Value) -> Result<Vec<RuntimeCatalogAuthor>, RuntimeError> {
    let values = array(value)?;
    if values.is_empty() || values.len() > 32 {
        return Err(RuntimeError::CatalogInvalid);
    }
    let mut ids = HashSet::new();
    let mut result = Vec::new();
    for value in values {
        let (login, id, kind) = parse_github_identity(value, true, false)?;
        if !ids.insert(id) {
            return Err(RuntimeError::CatalogInvalid);
        }
        result.push(RuntimeCatalogAuthor {
            github_login: login,
            github_id: id,
            github_type: match kind.as_str() {
                "User" => RuntimeCatalogAuthorKind::User,
                "Organization" => RuntimeCatalogAuthorKind::Organization,
                _ => return Err(RuntimeError::CatalogInvalid),
            },
        });
    }
    Ok(result)
}

// Parses one compact OCI or native Engine projection.
fn parse_engine_distribution(
    value: &Value,
    target_platform: &str,
) -> Result<RuntimeCatalogEngineDistribution, RuntimeError> {
    let root = object(value)?;
    match string(root, "kind")? {
        "oci-container" => {
            require_optional_fields(root, &["kind", "reference"], &["payload_id"])?;
            let reference_value = string(root, "reference")?;
            if !is_registry_source(reference_value) {
                return Err(RuntimeError::CatalogInvalid);
            }
            let reference =
                RuntimeSource::parse(reference_value).map_err(|_| RuntimeError::CatalogInvalid)?;
            let payload_id = optional_sha256_id(root, "payload_id")?;
            Ok(RuntimeCatalogEngineDistribution::Oci {
                reference,
                payload_id,
            })
        }
        kind @ ("native-archive" | "python-standalone" | "embedded-application") => {
            require_fields(root, &["kind", "payload_id", "platform", "source_revision"])?;
            let platform = string(root, "platform")?;
            if !is_platform(platform) || platform != target_platform {
                return Err(RuntimeError::CatalogInvalid);
            }
            let payload_id = sha256_id(string(root, "payload_id")?)?;
            let source_revision = ArtifactRevision::parse(string(root, "source_revision")?)
                .map_err(|_| RuntimeError::CatalogInvalid)?;
            let kind = match kind {
                "native-archive" => NativeEngineKind::NativeArchive,
                "python-standalone" => NativeEngineKind::PythonStandalone,
                "embedded-application" => NativeEngineKind::EmbeddedApplication,
                _ => unreachable!(),
            };
            Ok(RuntimeCatalogEngineDistribution::Native {
                kind,
                platform: platform.to_string(),
                payload_id,
                source_revision,
            })
        }
        _ => Err(RuntimeError::CatalogInvalid),
    }
}

// Parses one optional benchmark projection and preserves its exact score bits.
fn parse_benchmark(value: &Value) -> Result<Option<u64>, RuntimeError> {
    if value.is_null() {
        return Ok(None);
    }
    let benchmark = object(value)?;
    require_fields(benchmark, &["id", "score", "suite"])?;
    if !is_lower_hex(string(benchmark, "id")?, 64)
        || string(benchmark, "suite")? != RECOMMENDATION_SUITE
    {
        return Err(RuntimeError::CatalogInvalid);
    }
    let score = benchmark
        .get("score")
        .and_then(Value::as_f64)
        .filter(|value| value.is_finite() && *value > 0.0)
        .ok_or(RuntimeError::CatalogInvalid)?;
    Ok(Some(score.to_bits()))
}

// Validates every supported qualification projection and returns its revocation identity.
fn validate_qualification(
    candidate_id: &str,
    version: &str,
    benchmark_score_bits: Option<u64>,
    provenance_value: &Value,
    verification_value: &Value,
    source: &str,
) -> Result<(String, Option<Sha256Digest>), RuntimeError> {
    let provenance = object(provenance_value)?;
    let verification = object(verification_value)?;
    let method = string(verification, "method")?;
    let consensus = match method {
        "maintainer-qualified-pre-community-v1" => {
            require_fields(verification, &["method", "verifiers"])?;
            require_fields(
                provenance,
                &[
                    "method",
                    "proposal_head_sha",
                    "pull_request",
                    "pull_request_url",
                    "qualified_commit_sha",
                    "repository",
                ],
            )?;
            if string(provenance, "method")? != method
                || !array(
                    verification
                        .get("verifiers")
                        .ok_or(RuntimeError::CatalogInvalid)?,
                )?
                .is_empty()
            {
                return Err(RuntimeError::CatalogInvalid);
            }
            None
        }
        "community-consensus-v1" => {
            require_fields(
                verification,
                &["consensus_path", "consensus_sha256", "method", "verifiers"],
            )?;
            require_fields(provenance, &standard_provenance_fields())?;
            let verifiers = parse_verifiers(verification)?;
            if verifiers.len() < 3 {
                return Err(RuntimeError::CatalogInvalid);
            }
            Some(validate_consensus(candidate_id, provenance, verification)?)
        }
        "community-two-independent-v1"
        | "maintainer-waiver-one-independent-v1"
        | "allowlisted-maintainer-bypass-v1" => {
            let waived = method != "community-two-independent-v1";
            let verifiers = parse_verifiers(verification)?;
            let author_benchmark = method == "allowlisted-maintainer-bypass-v1"
                && verifiers.is_empty()
                && benchmark_score_bits.is_some();
            let mut fields = vec!["consensus_path", "consensus_sha256", "method", "verifiers"];
            if waived {
                fields.push("waiver");
            }
            if author_benchmark {
                fields.push("benchmark_source");
            }
            require_fields(verification, &fields)?;
            require_fields(provenance, &standard_provenance_fields())?;
            if (method == "community-two-independent-v1" && verifiers.len() != 2)
                || (method == "maintainer-waiver-one-independent-v1" && verifiers.len() != 1)
                || (method == "allowlisted-maintainer-bypass-v1" && verifiers.len() > 2)
                || (author_benchmark
                    && string(verification, "benchmark_source")? != "author-benchmark-v1")
            {
                return Err(RuntimeError::CatalogInvalid);
            }
            if waived {
                validate_waiver(
                    verification
                        .get("waiver")
                        .ok_or(RuntimeError::CatalogInvalid)?,
                    unsigned(provenance, "pull_request")?,
                    if method == "maintainer-waiver-one-independent-v1" {
                        "maintainer-one-independent-pass-v1"
                    } else {
                        "allowlisted-maintainer-bypass-v1"
                    },
                )?;
            }
            Some(validate_consensus(candidate_id, provenance, verification)?)
        }
        "runtime-contract-migration-v1" => {
            let has_consensus = verification.contains_key("consensus_sha256")
                || provenance.contains_key("consensus_sha256");
            let mut verification_fields = vec![
                "benchmark_record_path",
                "benchmark_record_sha256",
                "execution_contract_sha256",
                "from_source",
                "from_version",
                "method",
                "verifiers",
            ];
            let mut provenance_fields = vec![
                "benchmark_record_sha256",
                "execution_contract_sha256",
                "from_source",
                "from_version",
                "method",
                "proposal_head_sha",
                "pull_request",
                "pull_request_url",
                "qualified_commit_sha",
                "repository",
            ];
            if has_consensus {
                verification_fields.push("consensus_sha256");
                provenance_fields.push("consensus_sha256");
            }
            require_fields(verification, &verification_fields)?;
            require_fields(provenance, &provenance_fields)?;
            parse_verifiers(verification)?;
            let from_version = string(verification, "from_version")?;
            if string(provenance, "method")? != method
                || !is_version(from_version)
                || compare_versions(from_version, version) != Ordering::Less
                || string(verification, "from_source")? != string(provenance, "from_source")?
                || !is_registry_source(string(verification, "from_source")?)
                || string(verification, "from_source")? == source
                || string(verification, "benchmark_record_path")?
                    != format!("{candidate_id}/benchmark.previous.json")
                || !equal_sha256(verification, provenance, "benchmark_record_sha256")?
                || !equal_sha256(verification, provenance, "execution_contract_sha256")?
            {
                return Err(RuntimeError::CatalogInvalid);
            }
            if has_consensus {
                Some(equal_consensus(provenance, verification)?)
            } else {
                None
            }
        }
        _ => return Err(RuntimeError::CatalogInvalid),
    };
    validate_provenance_identity(provenance)?;
    let verifier_count = array(
        verification
            .get("verifiers")
            .ok_or(RuntimeError::CatalogInvalid)?,
    )?
    .len();
    if benchmark_score_bits.is_none()
        && !(method == "allowlisted-maintainer-bypass-v1" && verifier_count == 0)
    {
        return Err(RuntimeError::CatalogInvalid);
    }
    Ok((method.to_string(), consensus))
}

// Validates the common provenance repository, pull request, and commit identities.
fn validate_provenance_identity(provenance: &Map<String, Value>) -> Result<(), RuntimeError> {
    let pull_request = unsigned(provenance, "pull_request")?;
    if pull_request == 0
        || string(provenance, "repository")? != "letsinferlabs/runtimes"
        || string(provenance, "pull_request_url")?
            != format!("https://github.com/letsinferlabs/runtimes/pull/{pull_request}")
        || !is_lower_hex(string(provenance, "proposal_head_sha")?, 40)
        || !is_lower_hex(string(provenance, "qualified_commit_sha")?, 40)
    {
        return Err(RuntimeError::CatalogInvalid);
    }
    if let Some(value) = provenance.get("execution_sha256") {
        if !value.as_str().is_some_and(|value| is_lower_hex(value, 64)) {
            return Err(RuntimeError::CatalogInvalid);
        }
    }
    Ok(())
}

// Validates one consensus path and its equality across verification and provenance.
fn validate_consensus(
    candidate_id: &str,
    provenance: &Map<String, Value>,
    verification: &Map<String, Value>,
) -> Result<Sha256Digest, RuntimeError> {
    if string(verification, "consensus_path")? != format!("{candidate_id}/benchmark.consensus.json")
    {
        return Err(RuntimeError::CatalogInvalid);
    }
    equal_consensus(provenance, verification)
}

// Returns one consensus digest only when both qualification projections agree.
fn equal_consensus(
    provenance: &Map<String, Value>,
    verification: &Map<String, Value>,
) -> Result<Sha256Digest, RuntimeError> {
    let value = string(verification, "consensus_sha256")?;
    if string(provenance, "consensus_sha256")? != value || !is_lower_hex(value, 64) {
        return Err(RuntimeError::CatalogInvalid);
    }
    Sha256Digest::parse(value).map_err(|_| RuntimeError::CatalogInvalid)
}

// Validates one array of unique user verifier identities.
fn parse_verifiers(value: &Map<String, Value>) -> Result<Vec<u64>, RuntimeError> {
    let values = array(value.get("verifiers").ok_or(RuntimeError::CatalogInvalid)?)?;
    if values.len() > 64 {
        return Err(RuntimeError::CatalogInvalid);
    }
    let mut result = Vec::new();
    for value in values {
        let (_, id, _) = parse_github_identity(value, false, false)?;
        if result.contains(&id) {
            return Err(RuntimeError::CatalogInvalid);
        }
        result.push(id);
    }
    Ok(result)
}

// Validates one immutable maintainer-waiver projection.
fn validate_waiver(value: &Value, pull_request: u64, policy: &str) -> Result<(), RuntimeError> {
    let waiver = object(value)?;
    require_fields(
        waiver,
        &[
            "actor",
            "comment_id",
            "comment_url",
            "issued_at",
            "policy",
            "reason",
            "schema_version",
        ],
    )?;
    let comment_id = unsigned(waiver, "comment_id")?;
    let reason = string(waiver, "reason")?;
    if unsigned(waiver, "schema_version")? != 1
        || string(waiver, "policy")? != policy
        || reason.trim().is_empty()
        || reason.len() > 1_000
        || comment_id == 0
        || string(waiver, "comment_url")?
            != format!("https://github.com/letsinferlabs/runtimes/pull/{pull_request}#issuecomment-{comment_id}")
        || !is_utc_timestamp(string(waiver, "issued_at")?)
    {
        return Err(RuntimeError::CatalogInvalid);
    }
    parse_github_identity(
        waiver.get("actor").ok_or(RuntimeError::CatalogInvalid)?,
        false,
        false,
    )?;
    Ok(())
}

// Parses one signed schema-1 revocation ledger and its canonical entry order.
pub(crate) fn parse_revocations(bytes: &[u8]) -> Result<RevocationLedger, RuntimeError> {
    if bytes.is_empty() || bytes.len() > MAXIMUM_LEDGER_BYTES as usize {
        return Err(RuntimeError::CatalogInvalid);
    }
    let value = parse_closed_json(bytes).map_err(|_| RuntimeError::CatalogInvalid)?;
    let root = object(&value)?;
    require_fields(
        root,
        &[
            "generated_at_unix",
            "revocations",
            "schema_version",
            "sequence",
        ],
    )?;
    if unsigned(root, "schema_version")? != 1 {
        return Err(RuntimeError::CatalogInvalid);
    }
    let sequence = unsigned(root, "sequence")?;
    unsigned(root, "generated_at_unix")?;
    let values = array(
        root.get("revocations")
            .ok_or(RuntimeError::CatalogInvalid)?,
    )?;
    let mut entries = BTreeSet::new();
    let mut ordered = Vec::new();
    for value in values {
        let entry = object(value)?;
        require_fields(
            entry,
            &[
                "actor",
                "consensus_sha256",
                "reason_code",
                "replacement",
                "revoked_at_unix",
                "runtime_oci_digest",
                "verification_ids",
            ],
        )?;
        let runtime_digest = string(entry, "runtime_oci_digest")?;
        let consensus = string(entry, "consensus_sha256")?;
        if !is_sha256_id(runtime_digest)
            || !is_lower_hex(consensus, 64)
            || unsigned(entry, "revoked_at_unix")? == 0
            || !is_revocation_reason(string(entry, "reason_code")?)
        {
            return Err(RuntimeError::CatalogInvalid);
        }
        parse_github_identity(
            entry.get("actor").ok_or(RuntimeError::CatalogInvalid)?,
            true,
            true,
        )?;
        validate_verification_ids(
            entry
                .get("verification_ids")
                .ok_or(RuntimeError::CatalogInvalid)?,
        )?;
        validate_replacement(
            entry
                .get("replacement")
                .ok_or(RuntimeError::CatalogInvalid)?,
        )?;
        let identity = (runtime_digest.to_string(), consensus.to_string());
        if !entries.insert(identity.clone()) {
            return Err(RuntimeError::CatalogInvalid);
        }
        ordered.push(identity);
    }
    if ordered.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(RuntimeError::CatalogInvalid);
    }
    Ok(RevocationLedger { sequence, entries })
}

// Validates the sorted unique evidence identities retained by one revocation.
fn validate_verification_ids(value: &Value) -> Result<(), RuntimeError> {
    let values = array(value)?;
    if values.is_empty() {
        return Err(RuntimeError::CatalogInvalid);
    }
    let mut previous: Option<&str> = None;
    for value in values {
        let value = value.as_str().ok_or(RuntimeError::CatalogInvalid)?;
        if !is_lower_hex(value, 64) || previous.is_some_and(|previous| previous >= value) {
            return Err(RuntimeError::CatalogInvalid);
        }
        previous = Some(value);
    }
    Ok(())
}

// Validates an optional immutable replacement hint without following it automatically.
fn validate_replacement(value: &Value) -> Result<(), RuntimeError> {
    if value.is_null() {
        return Ok(());
    }
    let replacement = object(value)?;
    require_fields(replacement, &["candidate", "source", "version"])?;
    string(replacement, "candidate")?;
    if !is_version(string(replacement, "version")?)
        || !is_registry_source(string(replacement, "source")?)
    {
        return Err(RuntimeError::CatalogInvalid);
    }
    Ok(())
}

// Applies exact release revocations and recomputes active latest and recommendation views.
pub(crate) fn apply_revocations(
    catalog: ParsedCatalog,
    ledger: &RevocationLedger,
) -> Result<ActiveCatalog, RuntimeError> {
    let mut models = catalog.models;
    for model in models.values_mut() {
        for target in model.targets.values_mut() {
            target.candidates.retain(|_, candidate| {
                candidate.releases.retain(|_, release| {
                    let Some(consensus) = &release.consensus_sha256 else {
                        return true;
                    };
                    let digest = release
                        .source
                        .as_str()
                        .rsplit_once('@')
                        .map(|(_, digest)| digest)
                        .unwrap_or_default();
                    !ledger
                        .entries
                        .contains(&(digest.to_string(), consensus.as_str().to_string()))
                });
                if let Some(latest) = latest_version(&candidate.releases) {
                    candidate.latest = latest;
                    true
                } else {
                    false
                }
            });
            target.recommended = active_recommendation(&target.candidates);
        }
    }
    Ok(ActiveCatalog {
        targets: catalog.targets,
        models,
    })
}

// Chooses the exact active scored release using score, version, candidate, and version order.
fn active_recommendation(
    candidates: &BTreeMap<String, ParsedCandidate>,
) -> Option<(String, String)> {
    let mut choices = Vec::new();
    for (candidate, record) in candidates {
        for (version, release) in &record.releases {
            if let Some(score) = release.benchmark_score_bits.map(f64::from_bits) {
                choices.push((score, version.clone(), candidate.clone()));
            }
        }
    }
    choices
        .into_iter()
        .max_by(|left, right| {
            left.0
                .partial_cmp(&right.0)
                .unwrap_or(Ordering::Equal)
                .then_with(|| compare_revocation_versions(&left.1, &right.1))
                .then_with(|| left.2.cmp(&right.2))
                .then_with(|| left.1.cmp(&right.1))
        })
        .map(|(_, version, candidate)| (candidate, version))
}

// Builds one public list entry from an already validated active release.
fn list_entry(
    model: &str,
    target: &RuntimeCatalogTarget,
    candidate_id: &str,
    version: &str,
    release: &ParsedRelease,
    recommended: bool,
) -> RuntimeCatalogListEntry {
    RuntimeCatalogListEntry {
        logical_model: LogicalModelName::parse(model).expect("validated model"),
        target: target.clone(),
        candidate_id: RuntimeCandidateId::parse(candidate_id).expect("validated candidate"),
        version: version.to_string(),
        source: release.source.clone(),
        engine: release.engine.clone(),
        engine_distribution: release.engine_distribution.clone(),
        model_uri: release.model_uri.clone(),
        authors: release.authors.clone(),
        license: release.license.clone(),
        benchmark_score_bits: release.benchmark_score_bits,
        provenance: release.provenance.clone(),
        verification: release.verification.clone(),
        verification_method: release.verification_method.clone(),
        consensus_sha256: release.consensus_sha256.clone(),
        recommended,
    }
}

// Returns versions in descending semantic order.
fn sorted_versions(releases: &BTreeMap<String, ParsedRelease>) -> Vec<String> {
    let mut versions: Vec<_> = releases.keys().cloned().collect();
    versions.sort_by(|left, right| compare_versions(right, left));
    versions
}

// Returns the greatest semantic version in one non-empty release map.
fn latest_version(releases: &BTreeMap<String, ParsedRelease>) -> Option<String> {
    releases
        .keys()
        .max_by(|left, right| compare_revocation_versions(left, right))
        .cloned()
}

// Compares versions exactly as the production active-revocation projection does.
fn compare_revocation_versions(left: &str, right: &str) -> Ordering {
    revocation_version_key(left).cmp(&revocation_version_key(right))
}

// Returns the historical active-revocation ordering key used by Python Core.
fn revocation_version_key(value: &str) -> (u64, u64, u64, Vec<(u8, String)>) {
    let suffix_index = value.find(['-', '+']);
    let (core, suffix) = suffix_index.map_or((value, None), |index| {
        (&value[..index], Some(&value[index + 1..]))
    });
    let mut numeric = core.split('.').map(|part| part.parse::<u64>().unwrap_or(0));
    let suffix = suffix.map_or_else(Vec::new, |suffix| {
        suffix
            .split('.')
            .map(|part| {
                if part.bytes().all(|byte| byte.is_ascii_digit()) {
                    (
                        1,
                        format!("{:020}", part.parse::<u64>().unwrap_or(u64::MAX)),
                    )
                } else {
                    (0, part.to_string())
                }
            })
            .collect()
    });
    (
        numeric.next().unwrap_or(0),
        numeric.next().unwrap_or(0),
        numeric.next().unwrap_or(0),
        suffix,
    )
}

// Compares semantic versions with release versions greater than prereleases.
fn compare_versions(left: &str, right: &str) -> Ordering {
    semantic_version_key(left).cmp(&semantic_version_key(right))
}

// Returns one sortable semantic-version key for already validated input.
fn semantic_version_key(value: &str) -> (u64, u64, u64, Vec<(u8, String)>) {
    let without_build = value.split_once('+').map_or(value, |(core, _)| core);
    let (core, prerelease) = without_build
        .split_once('-')
        .map_or((without_build, None), |(core, suffix)| (core, Some(suffix)));
    let mut numeric = core.split('.').map(|part| part.parse::<u64>().unwrap_or(0));
    let mut suffix = match prerelease {
        None => vec![(2, String::new())],
        Some(_) => vec![(0, String::new())],
    };
    if let Some(prerelease) = prerelease {
        suffix.extend(prerelease.split('.').map(|part| {
            if part.bytes().all(|byte| byte.is_ascii_digit()) {
                (
                    0,
                    format!("{:020}", part.parse::<u64>().unwrap_or(u64::MAX)),
                )
            } else {
                (1, part.to_string())
            }
        }));
    }
    (
        numeric.next().unwrap_or(0),
        numeric.next().unwrap_or(0),
        numeric.next().unwrap_or(0),
        suffix,
    )
}

// Returns the canonical platform string for one hardware observation.
pub(crate) fn platform_name(hardware: &HardwareObservation) -> String {
    let operating_system = match hardware.platform().operating_system() {
        OperatingSystem::Linux => "linux",
        OperatingSystem::Macos => "macos",
    };
    let architecture = match hardware.platform().architecture() {
        CpuArchitecture::Arm64 => "arm64",
        CpuArchitecture::X86_64 => "x86_64",
    };
    format!("{operating_system}/{architecture}")
}

// Returns the canonical platform string for one supported immutable platform identity.
pub(crate) fn platform_identity_name(platform: PlatformIdentity) -> String {
    let operating_system = match platform.operating_system() {
        OperatingSystem::Linux => "linux",
        OperatingSystem::Macos => "macos",
    };
    let architecture = match platform.architecture() {
        CpuArchitecture::Arm64 => "arm64",
        CpuArchitecture::X86_64 => "x86_64",
    };
    format!("{operating_system}/{architecture}")
}

// Returns whether one observed accelerator vendor equals the target identity.
pub(crate) fn catalog_vendor_matches(
    observed: &li_core_interface::AcceleratorVendor,
    required: &str,
) -> bool {
    match observed {
        li_core_interface::AcceleratorVendor::Nvidia => required == "nvidia",
        li_core_interface::AcceleratorVendor::Apple => required == "apple",
        li_core_interface::AcceleratorVendor::Other(value) => value.as_str() == required,
    }
}

// Returns whether one observed compute identity equals the portable target architecture.
pub(crate) fn catalog_compute_matches(
    observed: &li_core_interface::ComputeCapability,
    required: &str,
) -> bool {
    match observed {
        li_core_interface::ComputeCapability::Cuda { architecture, .. } => {
            architecture.as_str() == required
        }
        li_core_interface::ComputeCapability::Metal { family, .. } => {
            required == "apple-silicon" || family.as_str() == required
        }
        li_core_interface::ComputeCapability::Other { capability, .. } => capability
            .as_ref()
            .is_some_and(|value| value.as_str() == required),
    }
}

// Parses one exact GitHub actor identity with explicit account-type policy.
fn parse_github_identity(
    value: &Value,
    allow_organization: bool,
    allow_bot: bool,
) -> Result<(String, u64, String), RuntimeError> {
    let root = object(value)?;
    require_fields(root, &["github_id", "github_login", "github_type"])?;
    let login = string(root, "github_login")?;
    let id = unsigned(root, "github_id")?;
    let kind = string(root, "github_type")?;
    if id == 0
        || !is_github_login(login)
        || !matches!(kind, "User" | "Organization" | "Bot")
        || (kind == "Organization" && !allow_organization)
        || (kind == "Bot" && !allow_bot)
    {
        return Err(RuntimeError::CatalogInvalid);
    }
    Ok((login.to_string(), id, kind.to_string()))
}

// Returns the standard community provenance field set.
fn standard_provenance_fields() -> Vec<&'static str> {
    vec![
        "consensus_sha256",
        "execution_sha256",
        "proposal_head_sha",
        "pull_request",
        "pull_request_url",
        "qualified_commit_sha",
        "repository",
    ]
}

// Requires equal SHA-256 fields across two projections.
fn equal_sha256(
    left: &Map<String, Value>,
    right: &Map<String, Value>,
    field: &str,
) -> Result<bool, RuntimeError> {
    let value = string(left, field)?;
    Ok(is_lower_hex(value, 64) && string(right, field)? == value)
}

// Parses one optional positive unsigned field.
fn optional_positive(
    object: &Map<String, Value>,
    field: &str,
) -> Result<Option<u64>, RuntimeError> {
    object
        .get(field)
        .map(|_| unsigned(object, field).and_then(positive).map(Some))
        .unwrap_or(Ok(None))
}

// Parses one optional algorithm-prefixed SHA-256 field.
fn optional_sha256_id(
    object: &Map<String, Value>,
    field: &str,
) -> Result<Option<Sha256Digest>, RuntimeError> {
    object
        .get(field)
        .map(|_| string(object, field).and_then(sha256_id).map(Some))
        .unwrap_or(Ok(None))
}

// Parses one algorithm-prefixed SHA-256 value.
fn sha256_id(value: &str) -> Result<Sha256Digest, RuntimeError> {
    value
        .strip_prefix("sha256:")
        .filter(|value| is_lower_hex(value, 64))
        .ok_or(RuntimeError::CatalogInvalid)
        .and_then(|value| Sha256Digest::parse(value).map_err(|_| RuntimeError::CatalogInvalid))
}

// Converts a positive GiB quantity into a checked byte count.
pub(crate) fn gibibytes(value: u64) -> Result<ByteCount, RuntimeError> {
    value
        .checked_mul(1 << 30)
        .and_then(|value| ByteCount::new(value).ok())
        .ok_or(RuntimeError::CatalogInvalid)
}

// Rejects duplicate object keys while retaining an ordinary serde_json value tree.
pub(crate) fn parse_closed_json(bytes: &[u8]) -> Result<Value, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = ClosedJsonValue::deserialize(&mut deserializer)?.0;
    deserializer.end()?;
    Ok(value)
}

struct ClosedJsonValue(Value);

impl<'de> Deserialize<'de> for ClosedJsonValue {
    // Deserializes every JSON value through a duplicate-rejecting visitor.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(ClosedJsonVisitor)
    }
}

struct ClosedJsonVisitor;

impl<'de> Visitor<'de> for ClosedJsonVisitor {
    type Value = ClosedJsonValue;

    // Describes the complete JSON value grammar accepted by this visitor.
    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    // Preserves JSON null.
    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(ClosedJsonValue(Value::Null))
    }

    // Preserves one boolean.
    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(ClosedJsonValue(Value::Bool(value)))
    }

    // Preserves one signed integer.
    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(ClosedJsonValue(Value::Number(Number::from(value))))
    }

    // Preserves one unsigned integer.
    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(ClosedJsonValue(Value::Number(Number::from(value))))
    }

    // Preserves one finite JSON floating-point number.
    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .map(ClosedJsonValue)
            .ok_or_else(|| E::custom("JSON number is not finite"))
    }

    // Preserves one borrowed string.
    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(ClosedJsonValue(Value::String(value.to_string())))
    }

    // Preserves one owned string.
    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(ClosedJsonValue(Value::String(value)))
    }

    // Preserves one array while recursively rejecting duplicate object keys.
    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<ClosedJsonValue>()? {
            values.push(value.0);
        }
        Ok(ClosedJsonValue(Value::Array(values)))
    }

    // Preserves one object and rejects its first repeated key.
    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some((key, value)) = map.next_entry::<String, ClosedJsonValue>()? {
            if values.insert(key.clone(), value.0).is_some() {
                return Err(de::Error::custom(format!("duplicate JSON key: {key}")));
            }
        }
        Ok(ClosedJsonValue(Value::Object(values)))
    }
}

// Returns one JSON object or a stable catalog failure.
pub(crate) fn object(value: &Value) -> Result<&Map<String, Value>, RuntimeError> {
    value.as_object().ok_or(RuntimeError::CatalogInvalid)
}

// Returns one JSON array or a stable catalog failure.
fn array(value: &Value) -> Result<&Vec<Value>, RuntimeError> {
    value.as_array().ok_or(RuntimeError::CatalogInvalid)
}

// Returns one required string field.
pub(crate) fn string<'a>(
    object: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a str, RuntimeError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or(RuntimeError::CatalogInvalid)
}

// Returns one required unsigned-integer field without accepting booleans or floats.
pub(crate) fn unsigned(object: &Map<String, Value>, field: &str) -> Result<u64, RuntimeError> {
    object
        .get(field)
        .and_then(Value::as_u64)
        .ok_or(RuntimeError::CatalogInvalid)
}

// Returns one required boolean field.
fn boolean(object: &Map<String, Value>, field: &str) -> Result<bool, RuntimeError> {
    object
        .get(field)
        .and_then(Value::as_bool)
        .ok_or(RuntimeError::CatalogInvalid)
}

// Requires one object to contain exactly the named fields.
pub(crate) fn require_fields(
    object: &Map<String, Value>,
    fields: &[&str],
) -> Result<(), RuntimeError> {
    let expected: BTreeSet<_> = fields.iter().copied().collect();
    let actual: BTreeSet<_> = object.keys().map(String::as_str).collect();
    if actual != expected {
        return Err(RuntimeError::CatalogInvalid);
    }
    Ok(())
}

// Requires one object to contain every required field and only listed optional fields.
fn require_optional_fields(
    object: &Map<String, Value>,
    required: &[&str],
    optional: &[&str],
) -> Result<(), RuntimeError> {
    let required: BTreeSet<_> = required.iter().copied().collect();
    let allowed: BTreeSet<_> = required
        .iter()
        .copied()
        .chain(optional.iter().copied())
        .collect();
    let actual: BTreeSet<_> = object.keys().map(String::as_str).collect();
    if !required.is_subset(&actual) || !actual.is_subset(&allowed) {
        return Err(RuntimeError::CatalogInvalid);
    }
    Ok(())
}

// Returns one positive unsigned quantity.
fn positive(value: u64) -> Result<u64, RuntimeError> {
    (value > 0)
        .then_some(value)
        .ok_or(RuntimeError::CatalogInvalid)
}

// Returns one bounded positive u16 quantity.
fn bounded_u16(value: u64, minimum: u16, maximum: u16) -> Result<u16, RuntimeError> {
    let value = u16::try_from(value).map_err(|_| RuntimeError::CatalogInvalid)?;
    (minimum..=maximum)
        .contains(&value)
        .then_some(value)
        .ok_or(RuntimeError::CatalogInvalid)
}

// Returns whether one value is a lowercase safe technical name.
fn is_safe_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

// Returns whether one value is a canonical supported platform string.
fn is_platform(value: &str) -> bool {
    value.split_once('/').is_some_and(|(left, right)| {
        is_safe_name(left) && is_safe_name(right) && !right.contains('/')
    })
}

// Returns whether one value is one bounded credential-free HTTPS URL.
pub(crate) fn is_https_url(value: &str) -> bool {
    if value.len() > 2_048
        || value.chars().any(char::is_whitespace)
        || value.chars().any(char::is_control)
        || value.contains('@')
        || value.contains('#')
    {
        return false;
    }
    value.strip_prefix("https://").is_some_and(|remainder| {
        let authority = remainder.split('/').next().unwrap_or_default();
        !authority.is_empty()
            && authority != "."
            && authority != ".."
            && !authority.starts_with(':')
    })
}

// Returns whether one string contains exact lowercase hexadecimal bytes.
pub(crate) fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

// Returns whether one value is an algorithm-prefixed SHA-256 digest.
fn is_sha256_id(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|value| is_lower_hex(value, 64))
}

// Returns whether one value is a digest-pinned registry reference.
fn is_registry_source(value: &str) -> bool {
    value
        .rsplit_once("@sha256:")
        .is_some_and(|(source, digest)| {
            !source.is_empty()
                && !source.chars().any(char::is_whitespace)
                && !source.contains('@')
                && is_lower_hex(digest, 64)
        })
}

// Returns whether one version follows the published bounded release grammar.
fn is_version(value: &str) -> bool {
    if value.is_empty() || value.len() > 128 {
        return false;
    }
    let (core, suffix) = value.find(['-', '+']).map_or((value, None), |index| {
        (&value[..index], Some(&value[index + 1..]))
    });
    let numeric: Vec<_> = core.split('.').collect();
    numeric.len() == 3
        && numeric
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
        && suffix.is_none_or(|suffix| {
            !suffix.is_empty()
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
        })
}

// Returns the exact owner and repository from one Hugging Face URI.
fn hugging_face_identity(value: &str) -> Result<(&str, &str), RuntimeError> {
    let value = value
        .strip_prefix("hf://")
        .ok_or(RuntimeError::CatalogInvalid)?;
    let (owner, repository) = value.split_once('/').ok_or(RuntimeError::CatalogInvalid)?;
    if owner.is_empty()
        || repository.is_empty()
        || repository.contains('/')
        || !owner.bytes().all(is_hugging_face_character)
        || !repository.bytes().all(is_hugging_face_character)
    {
        return Err(RuntimeError::CatalogInvalid);
    }
    Ok((owner, repository))
}

// Returns whether one byte is accepted in a Hugging Face owner or repository name.
fn is_hugging_face_character(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
}

// Returns whether one SPDX-shaped license identity is bounded and canonical.
fn is_license(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 127
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'-'))
}

// Returns whether one GitHub login follows the immutable identity projection grammar.
fn is_github_login(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 39
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

// Returns whether one timestamp follows the UTC publication projection grammar.
fn is_utc_timestamp(value: &str) -> bool {
    if !value.ends_with('Z') || value.len() < 20 || value.len() > 27 {
        return false;
    }
    let bytes = value.as_bytes();
    bytes.get(4) == Some(&b'-')
        && bytes.get(7) == Some(&b'-')
        && bytes.get(10) == Some(&b'T')
        && bytes.get(13) == Some(&b':')
        && bytes.get(16) == Some(&b':')
        && bytes[..19]
            .iter()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7 | 10 | 13 | 16) || byte.is_ascii_digit())
        && (value.len() == 20
            || (bytes.get(19) == Some(&b'.')
                && bytes[20..bytes.len() - 1].iter().all(u8::is_ascii_digit)))
}

// Returns whether one signed revocation reason is recognized by Core.
fn is_revocation_reason(value: &str) -> bool {
    matches!(
        value,
        "compromised-verifier-key"
            | "fraudulent-evidence"
            | "incorrect-target"
            | "invalid-benchmark-contract"
            | "output-correctness-failure"
            | "safety-failure"
            | "structurally-invalid-evidence"
    )
}
