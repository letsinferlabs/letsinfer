// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use li_benchmark_manager::{
    BenchmarkAuthorizationProvider, BenchmarkAuthorizationSource, BenchmarkCommunityAuthority,
    BenchmarkError, BenchmarkGitRevision, BenchmarkKind, BenchmarkNodeAuthority,
    BenchmarkRecordSchema, BenchmarkRequest, BenchmarkRunPlanProvider, BenchmarkRunPlanResolution,
    BenchmarkRunPlanSource, BenchmarkScope, BenchmarkSubject, BoundBenchmarkAuthorizationProvider,
    ResolvedBenchmarkRunPlanProvider,
};
use li_core_interface::{
    ArtifactName, ArtifactRevision, ArtifactUri, CredentialId, EndpointAddress, EndpointHealth,
    EndpointScheme, EngineDistribution, EntityTimestamps, EvidenceLabel, InstallationId,
    InterconnectKind, InterconnectRequirement, LogicalModelName, ModelArtifact,
    ModelArtifactFormat, ModelServiceDesiredState, ModelServiceId, NodeAddress, NodeId, NodeRole,
    NodeState, OperationId, PlacementEndpoint, PlacementGroup, PlacementGroupCapacity,
    PlacementGroupId, PlacementGroupState, PlacementId, PlatformIdentity, RuntimeCandidateId,
    RuntimeIdentity, RuntimeInstallation, RuntimeInstallationId, RuntimeInstallationState,
    RuntimeSource, RuntimeVersion, Sha256Digest, TargetId, TechnicalName, TokenCountContract,
    TokenCountProtocol, UnixMilliseconds,
};

// Stores exact authority call ordering and one replaceable community snapshot.
struct AuthorizationSourceMock {
    node: Mutex<Result<BenchmarkNodeAuthority, BenchmarkError>>,
    community: Mutex<Result<BenchmarkCommunityAuthority, BenchmarkError>>,
    calls: Mutex<Vec<&'static str>>,
}

impl BenchmarkAuthorizationSource for AuthorizationSourceMock {
    // Returns the configured Node snapshot and records that it was requested first.
    fn node_authority(
        &self,
        _job_id: &OperationId,
        _request: &BenchmarkRequest,
    ) -> Result<BenchmarkNodeAuthority, BenchmarkError> {
        self.calls.lock().expect("calls").push("node");
        self.node.lock().expect("node").clone()
    }

    // Returns the configured community snapshot only after Node admission succeeds.
    fn community_authority(
        &self,
        _job_id: &OperationId,
        _request: &BenchmarkRequest,
    ) -> Result<BenchmarkCommunityAuthority, BenchmarkError> {
        self.calls.lock().expect("calls").push("community");
        self.community.lock().expect("community").clone()
    }
}

// Supplies one exact plan resolution or one sensitive provider failure.
struct RunPlanSourceMock {
    resolution: Mutex<BenchmarkRunPlanResolution>,
    fail: AtomicBool,
    calls: AtomicUsize,
}

impl BenchmarkRunPlanSource for RunPlanSourceMock {
    // Returns the configured typed projection without inspecting another manager.
    fn resolve(
        &self,
        _job_id: &OperationId,
        _request: &BenchmarkRequest,
    ) -> Result<BenchmarkRunPlanResolution, BenchmarkError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail.load(Ordering::SeqCst) {
            return Err(BenchmarkError::provider(
                "secret_provider",
                "token=/private/runtime-secret",
            ));
        }
        Ok(self.resolution.lock().expect("resolution").clone())
    }
}

// Returns one exact lowercase digest fixture.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&character.to_string().repeat(64)).expect("digest")
}

// Returns one ordinary community-verification request.
fn verification_request() -> BenchmarkRequest {
    BenchmarkRequest::new(
        BenchmarkKind::verification(
            42,
            BenchmarkGitRevision::parse(&"a".repeat(40)).expect("head"),
            RuntimeCandidateId::parse("sglang--owner--model--target").expect("candidate"),
            OperationId::parse(&"d".repeat(32)).expect("transaction"),
            digest('e'),
            digest('f'),
            9001,
            digest('b'),
            Some(digest('c')),
        )
        .expect("verification"),
        BenchmarkScope::Complete,
        subject(),
    )
    .expect("request")
}

// Returns the exact authority matching the ordinary verification request.
fn community_authority(ready: bool, verified: bool) -> BenchmarkCommunityAuthority {
    BenchmarkCommunityAuthority::new(
        42,
        BenchmarkGitRevision::parse(&"a".repeat(40)).expect("head"),
        "sglang--owner--model--target",
        digest('f'),
        9001,
        digest('b'),
        Some(digest('c')),
        ready,
        verified,
    )
    .expect("authority")
}

// Returns one active main authorization source.
fn authorization_source() -> Arc<AuthorizationSourceMock> {
    Arc::new(AuthorizationSourceMock {
        node: Mutex::new(Ok(BenchmarkNodeAuthority::new(
            NodeId::parse(&"d".repeat(32)).expect("node"),
            NodeRole::Main,
            NodeState::Active,
        ))),
        community: Mutex::new(Ok(community_authority(true, true))),
        calls: Mutex::new(Vec::new()),
    })
}

// Proves local authorization binds the active main and never consults community state.
#[test]
fn authorization_admits_local_active_main_before_mode_specific_lookup() {
    let source = authorization_source();
    let provider = BoundBenchmarkAuthorizationProvider::new(source.clone());
    let request = BenchmarkRequest::new(BenchmarkKind::Local, BenchmarkScope::Complete, subject())
        .expect("request");
    let job_id = OperationId::parse(&"e".repeat(32)).expect("job");
    let first = provider.authorize(&job_id, &request).expect("authorize");
    let second = provider.authorize(&job_id, &request).expect("replay");

    assert_eq!(first, second);
    assert_eq!(*source.calls.lock().expect("calls"), vec!["node", "node"]);
}

// Proves Node denial precedes proposal lookup and community identity is exact and fail closed.
#[test]
fn authorization_denial_order_and_community_identity_are_exact() {
    let source = authorization_source();
    *source.node.lock().expect("node") = Ok(BenchmarkNodeAuthority::new(
        NodeId::parse(&"d".repeat(32)).expect("node"),
        NodeRole::Child,
        NodeState::Active,
    ));
    let provider = BoundBenchmarkAuthorizationProvider::new(source.clone());
    let job_id = OperationId::parse(&"e".repeat(32)).expect("job");
    let request = verification_request();
    assert_eq!(
        provider.authorize(&job_id, &request),
        Err(BenchmarkError::AuthorizationDenied)
    );
    assert_eq!(*source.calls.lock().expect("calls"), vec!["node"]);

    *source.node.lock().expect("node") = Ok(BenchmarkNodeAuthority::new(
        NodeId::parse(&"d".repeat(32)).expect("node"),
        NodeRole::Main,
        NodeState::Active,
    ));
    *source.community.lock().expect("community") = Ok(community_authority(false, true));
    assert_eq!(
        provider.authorize(&job_id, &request),
        Err(BenchmarkError::AuthorizationDenied)
    );
    *source.community.lock().expect("community") = Ok(community_authority(true, false));
    assert_eq!(
        provider.authorize(&job_id, &request),
        Err(BenchmarkError::AuthorizationDenied)
    );
    *source.community.lock().expect("community") = Ok(community_authority(true, true));
    assert!(provider.authorize(&job_id, &request).is_ok());
}

// Proves unavailable authority providers are redacted and never collapse into an approval.
#[test]
fn authorization_provider_substitution_is_redacted() {
    let source = authorization_source();
    *source.node.lock().expect("node") = Err(BenchmarkError::provider(
        "secret_provider",
        "credential=/private/token",
    ));
    let provider = BoundBenchmarkAuthorizationProvider::new(source);
    let request = BenchmarkRequest::new(BenchmarkKind::Local, BenchmarkScope::Complete, subject())
        .expect("request");
    assert_eq!(
        provider.authorize(&OperationId::parse(&"e".repeat(32)).expect("job"), &request,),
        Err(BenchmarkError::provider(
            "authorization",
            "authorization facts are unavailable",
        ))
    );
}

// Returns one exact benchmark subject matching the typed plan fixture.
fn subject() -> BenchmarkSubject {
    BenchmarkSubject::new(
        InstallationId::parse(&"1".repeat(64)).expect("Core installation"),
        RuntimeInstallationId::parse(&"2".repeat(32)).expect("runtime installation"),
        LogicalModelName::parse("qwen").expect("model"),
        PlacementGroupId::parse(&"3".repeat(32)).expect("placement group"),
        digest('4'),
        digest('5'),
        digest('6'),
    )
}

// Returns one exact Runtime identity for OCI or native execution.
fn runtime_identity(native: bool) -> RuntimeIdentity {
    let engine = if native {
        EngineDistribution::native(
            li_core_interface::NativeEngineKind::NativeArchive,
            PlatformIdentity::new(
                li_core_interface::OperatingSystem::Macos,
                li_core_interface::CpuArchitecture::Arm64,
            ),
            digest('7'),
            ArtifactRevision::parse(&"8".repeat(40)).expect("revision"),
        )
    } else {
        EngineDistribution::oci(
            RuntimeSource::parse(&format!("ghcr.io/engine@sha256:{}", "7".repeat(64)))
                .expect("Engine source"),
            digest('7'),
            None,
            Some(digest('8')),
        )
    };
    RuntimeIdentity::new(
        RuntimeCandidateId::parse("sglang--owner--model--target").expect("candidate"),
        RuntimeVersion::parse("1.0.0").expect("version"),
        TargetId::parse("target").expect("target"),
        RuntimeSource::parse(&format!("ghcr.io/runtime@sha256:{}", "9".repeat(64)))
            .expect("runtime source"),
        engine,
        digest('9'),
        digest('a'),
        digest('4'),
    )
    .expect("runtime")
}

// Returns one Available installation whose evidence label remains descriptive only.
fn runtime_installation(native: bool, evidence: EvidenceLabel) -> RuntimeInstallation {
    RuntimeInstallation::new(
        RuntimeInstallationId::parse(&"2".repeat(32)).expect("installation"),
        NodeId::parse(&"d".repeat(32)).expect("node"),
        LogicalModelName::parse("qwen").expect("model"),
        runtime_identity(native),
        vec![ModelArtifact::new(
            ArtifactName::parse("model").expect("name"),
            ArtifactUri::parse("hf://owner/model").expect("URI"),
            ArtifactRevision::parse(&"b".repeat(40)).expect("revision"),
            ModelArtifactFormat::HuggingFaceSnapshot,
        )],
        evidence,
        RuntimeInstallationState::Available,
        None,
        EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(1_000))
            .expect("timestamps"),
    )
    .expect("installation")
}

// Returns one stable running group with exact token-count capability.
fn placement_group(native: bool) -> PlacementGroup {
    let placement_id = PlacementId::parse(&"c".repeat(32)).expect("placement");
    let endpoint = PlacementEndpoint::new(
        placement_id.clone(),
        NodeId::parse(&"d".repeat(32)).expect("node"),
        EndpointAddress::new(
            EndpointScheme::Https,
            NodeAddress::parse("127.0.0.1").expect("address"),
            18_000,
        )
        .expect("endpoint"),
        CredentialId::parse(&"e".repeat(32)).expect("credential"),
        Some(CredentialId::parse(&"f".repeat(32)).expect("CA")),
        Some(
            TokenCountContract::new("/v1/letsinfer/token-count", TokenCountProtocol::LetsInferV1)
                .expect("token count"),
        ),
        4,
        262_144,
        EndpointHealth::new(true, false, Some(50_000), Vec::new()).expect("health"),
    )
    .expect("endpoint");
    PlacementGroup::new(
        PlacementGroupId::parse(&"3".repeat(32)).expect("group"),
        ModelServiceId::parse(&"0".repeat(32)).expect("service"),
        runtime_identity(native),
        vec![placement_id.clone()],
        placement_id,
        Some(endpoint),
        PlacementGroupCapacity::new(
            8,
            4,
            262_144,
            InterconnectRequirement::new(InterconnectKind::Any, false, 0, 0),
        )
        .expect("capacity"),
        ModelServiceDesiredState::Running,
        PlacementGroupState::Running,
        None,
        EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(1_000))
            .expect("timestamps"),
    )
    .expect("group")
}

// Returns one complete resolution for a selected Engine distribution and evidence label.
fn resolution(native: bool, evidence: EvidenceLabel) -> BenchmarkRunPlanResolution {
    BenchmarkRunPlanResolution::new(
        InstallationId::parse(&"1".repeat(64)).expect("Core installation"),
        runtime_installation(native, evidence),
        placement_group(native),
        digest('5'),
        digest('6'),
        vec![
            TechnicalName::parse("32k_c1").expect("cell"),
            TechnicalName::parse("32k_c2").expect("cell"),
        ],
        60_000,
        5_000,
    )
    .expect("resolution")
}

// Returns one configured plan provider and observable source.
fn plan_provider(
    resolution: BenchmarkRunPlanResolution,
) -> (ResolvedBenchmarkRunPlanProvider, Arc<RunPlanSourceMock>) {
    let source = Arc::new(RunPlanSourceMock {
        resolution: Mutex::new(resolution),
        fail: AtomicBool::new(false),
        calls: AtomicUsize::new(0),
    });
    (
        ResolvedBenchmarkRunPlanProvider::new(source.clone()),
        source,
    )
}

// Proves exact typed identities produce OCI/native plans and evidence labels never gate them.
#[test]
fn run_plan_binds_typed_runtime_and_placement_without_evidence_gating() {
    let job_id = OperationId::parse(&"e".repeat(32)).expect("job");
    let request = BenchmarkRequest::new(BenchmarkKind::Local, BenchmarkScope::Complete, subject())
        .expect("request");
    for evidence in [
        EvidenceLabel::Qualified,
        EvidenceLabel::Unqualified,
        EvidenceLabel::Unknown,
    ] {
        let (provider, _) = plan_provider(resolution(false, evidence));
        let plan = provider.plan(&job_id, &request).expect("OCI plan");
        assert_eq!(
            plan.record_schema(),
            BenchmarkRecordSchema::OciExecutionPayloadV7
        );
        assert_eq!(plan.total_cells(), 2);
    }
    let (native, _) = plan_provider(resolution(true, EvidenceLabel::Unknown));
    assert_eq!(
        native
            .plan(&job_id, &request)
            .expect("native plan")
            .record_schema(),
        BenchmarkRecordSchema::NativeExecutionPayloadV8,
    );
}

// Proves selected cells are an exact subset and every immutable subject identity is rebound.
#[test]
fn run_plan_rejects_unknown_cells_and_exact_identity_drift() {
    let job_id = OperationId::parse(&"e".repeat(32)).expect("job");
    let selected = BenchmarkRequest::new(
        BenchmarkKind::Local,
        BenchmarkScope::selected(vec![TechnicalName::parse("32k_c2").expect("cell")])
            .expect("scope"),
        subject(),
    )
    .expect("request");
    let (provider, _) = plan_provider(resolution(false, EvidenceLabel::Unqualified));
    assert_eq!(
        provider
            .plan(&job_id, &selected)
            .expect("selected")
            .total_cells(),
        1
    );

    let unknown = BenchmarkRequest::new(
        BenchmarkKind::Local,
        BenchmarkScope::selected(vec![TechnicalName::parse("64k_c1").expect("cell")])
            .expect("scope"),
        subject(),
    )
    .expect("request");
    assert!(matches!(
        provider.plan(&job_id, &unknown),
        Err(BenchmarkError::Provider { .. })
    ));

    let mismatched = BenchmarkRequest::new(
        BenchmarkKind::Local,
        BenchmarkScope::Complete,
        BenchmarkSubject::new(
            InstallationId::parse(&"1".repeat(64)).expect("Core installation"),
            RuntimeInstallationId::parse(&"2".repeat(32)).expect("installation"),
            LogicalModelName::parse("qwen").expect("model"),
            PlacementGroupId::parse(&"3".repeat(32)).expect("group"),
            digest('f'),
            digest('5'),
            digest('6'),
        ),
    )
    .expect("mismatched request");
    assert!(matches!(
        provider.plan(&job_id, &mismatched),
        Err(BenchmarkError::Provider { .. })
    ));
}

// Proves source substitution is redacted before any native plan can escape.
#[test]
fn run_plan_provider_substitution_is_redacted() {
    let (provider, source) = plan_provider(resolution(false, EvidenceLabel::Unknown));
    source.fail.store(true, Ordering::SeqCst);
    let request = BenchmarkRequest::new(BenchmarkKind::Local, BenchmarkScope::Complete, subject())
        .expect("request");
    assert_eq!(
        provider.plan(&OperationId::parse(&"e".repeat(32)).expect("job"), &request,),
        Err(BenchmarkError::provider(
            "execution",
            "benchmark run-plan inputs are unavailable",
        ))
    );
}
