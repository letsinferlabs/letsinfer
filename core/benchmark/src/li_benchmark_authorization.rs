// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use li_core_interface::{NodeId, NodeRole, NodeState, OperationId, Sha256Digest};

use crate::li_benchmark_execution::framed_digest;
use crate::{
    BenchmarkAuthorization, BenchmarkAuthorizationProvider, BenchmarkError, BenchmarkGitRevision,
    BenchmarkKind, BenchmarkRequest,
};

// Describes the exact local Node authority observed before benchmark admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BenchmarkNodeAuthority {
    node_id: NodeId,
    role: NodeRole,
    state: NodeState,
}

impl BenchmarkNodeAuthority {
    // Creates one immutable Node authority snapshot without interpreting it.
    pub const fn new(node_id: NodeId, role: NodeRole, state: NodeState) -> Self {
        Self {
            node_id,
            role,
            state,
        }
    }

    // Returns the exact local Node identity.
    pub const fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    // Returns the configured Node role.
    pub const fn role(&self) -> NodeRole {
        self.role
    }

    // Returns the current Node lifecycle state.
    pub const fn state(&self) -> NodeState {
        self.state
    }
}

// Describes one already-authenticated and supply-chain-verified proposal authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BenchmarkCommunityAuthority {
    pull_request: u64,
    proposal_head: BenchmarkGitRevision,
    candidate_id: String,
    candidate_subject_sha256: Sha256Digest,
    verifier_numeric_id: u64,
    device_id: Sha256Digest,
    baseline_execution_sha256: Option<Sha256Digest>,
    benchmark_ready: bool,
    verifier_bundle_verified: bool,
}

impl BenchmarkCommunityAuthority {
    // Creates one closed proposal snapshot without carrying GitHub credentials.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pull_request: u64,
        proposal_head: BenchmarkGitRevision,
        candidate_id: &str,
        candidate_subject_sha256: Sha256Digest,
        verifier_numeric_id: u64,
        device_id: Sha256Digest,
        baseline_execution_sha256: Option<Sha256Digest>,
        benchmark_ready: bool,
        verifier_bundle_verified: bool,
    ) -> Result<Self, BenchmarkError> {
        if pull_request == 0
            || verifier_numeric_id == 0
            || candidate_id.is_empty()
            || candidate_id.len() > 255
            || candidate_id.trim() != candidate_id
            || candidate_id.chars().any(char::is_control)
        {
            return Err(BenchmarkError::InvalidContract {
                reason: "benchmark community authority is invalid",
            });
        }
        Ok(Self {
            pull_request,
            proposal_head,
            candidate_id: candidate_id.to_string(),
            candidate_subject_sha256,
            verifier_numeric_id,
            device_id,
            baseline_execution_sha256,
            benchmark_ready,
            verifier_bundle_verified,
        })
    }

    // Returns whether this snapshot exactly authorizes the requested proposal identity.
    fn matches(&self, kind: &BenchmarkKind) -> bool {
        let BenchmarkKind::Verification {
            pull_request,
            proposal_head,
            candidate,
            candidate_subject_sha256,
            verifier_numeric_id,
            device_id,
            baseline_execution_sha256,
            ..
        } = kind
        else {
            return false;
        };
        self.pull_request == *pull_request
            && &self.proposal_head == proposal_head
            && self.candidate_id == candidate.as_str()
            && &self.candidate_subject_sha256 == candidate_subject_sha256
            && self.verifier_numeric_id == *verifier_numeric_id
            && &self.device_id == device_id
            && self.baseline_execution_sha256.as_ref() == baseline_execution_sha256.as_ref()
            && self.benchmark_ready
            && self.verifier_bundle_verified
    }

    // Returns the exact proposal identity fields used by the authorization receipt.
    fn receipt_fields(&self) -> [&str; 7] {
        [
            self.proposal_head.as_str(),
            self.candidate_id.as_str(),
            self.candidate_subject_sha256.as_str(),
            self.device_id.as_str(),
            self.baseline_execution_sha256
                .as_ref()
                .map_or("none", Sha256Digest::as_str),
            if self.benchmark_ready {
                "ready"
            } else {
                "not_ready"
            },
            if self.verifier_bundle_verified {
                "verified"
            } else {
                "unverified"
            },
        ]
    }
}

// Supplies authenticated Node and proposal facts without exposing mutable authority stores.
pub trait BenchmarkAuthorizationSource: Send + Sync {
    // Returns the current exact local Node authority before any community lookup.
    fn node_authority(
        &self,
        job_id: &OperationId,
        request: &BenchmarkRequest,
    ) -> Result<BenchmarkNodeAuthority, BenchmarkError>;

    // Returns the verified proposal authority for one community-verification request.
    fn community_authority(
        &self,
        job_id: &OperationId,
        request: &BenchmarkRequest,
    ) -> Result<BenchmarkCommunityAuthority, BenchmarkError>;
}

// Authorizes local and community work from exact injected authority snapshots.
pub struct BoundBenchmarkAuthorizationProvider {
    source: Arc<dyn BenchmarkAuthorizationSource>,
}

impl BoundBenchmarkAuthorizationProvider {
    // Creates one provider from the narrow authority source owned by Application composition.
    pub const fn new(source: Arc<dyn BenchmarkAuthorizationSource>) -> Self {
        Self { source }
    }

    // Reads and verifies the active local main authority before any mode-specific decision.
    fn active_main(
        &self,
        job_id: &OperationId,
        request: &BenchmarkRequest,
    ) -> Result<BenchmarkNodeAuthority, BenchmarkError> {
        let authority = self
            .source
            .node_authority(job_id, request)
            .map_err(|_| authorization_error())?;
        if authority.role() != NodeRole::Main || authority.state() != NodeState::Active {
            return Err(BenchmarkError::AuthorizationDenied);
        }
        Ok(authority)
    }
}

impl BenchmarkAuthorizationProvider for BoundBenchmarkAuthorizationProvider {
    // Admits an active-main local job or one exact ready and verified community proposal.
    fn authorize(
        &self,
        job_id: &OperationId,
        request: &BenchmarkRequest,
    ) -> Result<BenchmarkAuthorization, BenchmarkError> {
        let node = self.active_main(job_id, request)?;
        let request_sha256 = request.sha256()?;
        let receipt = match request.kind() {
            BenchmarkKind::Local => framed_digest(
                "li-benchmark-local-authorization-v1",
                &[
                    job_id.as_str(),
                    node.node_id().as_str(),
                    request_sha256.as_str(),
                ],
            ),
            verification @ BenchmarkKind::Verification {
                pull_request,
                verifier_numeric_id,
                ..
            } => {
                let authority = self
                    .source
                    .community_authority(job_id, request)
                    .map_err(|_| authorization_error())?;
                if !authority.matches(verification) {
                    return Err(BenchmarkError::AuthorizationDenied);
                }
                let fields = authority.receipt_fields();
                framed_digest(
                    "li-benchmark-community-authorization-v1",
                    &[
                        job_id.as_str(),
                        node.node_id().as_str(),
                        request_sha256.as_str(),
                        &pull_request.to_string(),
                        &verifier_numeric_id.to_string(),
                        fields[0],
                        fields[1],
                        fields[2],
                        fields[3],
                        fields[4],
                        fields[5],
                        fields[6],
                    ],
                )
            }
        };
        Ok(BenchmarkAuthorization::new(receipt))
    }
}

// Returns one stable redacted failure for an unavailable authority source.
fn authorization_error() -> BenchmarkError {
    BenchmarkError::provider("authorization", "authorization facts are unavailable")
}
