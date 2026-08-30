// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use li_benchmark_manager::{
    BenchmarkError, BenchmarkKind, BenchmarkRequest, BenchmarkScope, BenchmarkSubject,
    BenchmarkVerificationHandoffProvider, BenchmarkVerificationHandoffReceipt,
};
use li_core_interface::{OperationId, Sha256Digest};
use li_node_manager::{
    NodeBenchmarkCandidateHandoffCoordinator, NodeBenchmarkCandidateHandoffRequest,
};
use li_runtime_manager::{RuntimeExactCandidateArtifacts, RuntimeExactEngineArtifact};
use sha2::{Digest, Sha256};

use crate::{
    CoreBenchmarkVerificationCandidate, CoreBenchmarkVerificationCandidateHandoffPort,
    CoreBenchmarkVerificationEngineArtifact, CoreBenchmarkVerificationPreparationError,
    ResolvedCoreBenchmarkVerification,
};

// Converts trusted preparation bytes into Node-owned Runtime/Placement handoff operations.
pub struct ApplicationCoreBenchmarkVerificationHandoff {
    coordinator: Arc<NodeBenchmarkCandidateHandoffCoordinator>,
}

impl ApplicationCoreBenchmarkVerificationHandoff {
    // Creates one adapter without granting Node a dependency on Application types.
    pub const fn new(coordinator: Arc<NodeBenchmarkCandidateHandoffCoordinator>) -> Self {
        Self { coordinator }
    }

    // Acquires the exact candidate while retaining the active baseline and returns its subject.
    pub fn prepare_candidate(
        &self,
        resolved: &ResolvedCoreBenchmarkVerification,
        baseline: &BenchmarkSubject,
    ) -> Result<(OperationId, BenchmarkSubject), CoreBenchmarkVerificationPreparationError> {
        let transaction_id = resolved.transaction_id(baseline)?;
        let candidate = resolved.candidate();
        let request = NodeBenchmarkCandidateHandoffRequest::new(
            transaction_id.clone(),
            baseline.clone(),
            candidate.runtime().clone(),
            exact_artifacts(candidate)?,
            candidate
                .runtime()
                .runtime()
                .execution_contract_digest()
                .clone(),
        )
        .map_err(|_| CoreBenchmarkVerificationPreparationError::InvalidAuthority)?;
        self.coordinator
            .prepare(request)
            .map_err(|_| CoreBenchmarkVerificationPreparationError::Unavailable)?;
        let subject = self
            .coordinator
            .prepared_subject(&transaction_id)
            .map_err(|_| CoreBenchmarkVerificationPreparationError::Unavailable)?;
        if subject.model() != candidate.runtime().logical_model()
            || subject.execution_sha256()
                != candidate.runtime().runtime().execution_contract_digest()
        {
            return Err(CoreBenchmarkVerificationPreparationError::InvalidAuthority);
        }
        Ok((transaction_id, subject))
    }

    // Restores one prepared handoff after outer BenchmarkManager admission fails.
    pub fn abort(&self, transaction_id: &OperationId) -> Result<(), BenchmarkError> {
        self.coordinator
            .restore(transaction_id)
            .map(|_| ())
            .map_err(handoff_error)
    }
}

impl CoreBenchmarkVerificationCandidateHandoffPort for ApplicationCoreBenchmarkVerificationHandoff {
    // Delegates trusted closure conversion and exact candidate acquisition to Node handoff.
    fn prepare_candidate(
        &self,
        resolved: &ResolvedCoreBenchmarkVerification,
        baseline: &BenchmarkSubject,
    ) -> Result<(OperationId, BenchmarkSubject), CoreBenchmarkVerificationPreparationError> {
        ApplicationCoreBenchmarkVerificationHandoff::prepare_candidate(self, resolved, baseline)
    }

    // Restores one prepared handoff after failed outer manager admission.
    fn abort(&self, transaction_id: &OperationId) -> Result<(), BenchmarkError> {
        ApplicationCoreBenchmarkVerificationHandoff::abort(self, transaction_id)
    }
}

impl BenchmarkVerificationHandoffProvider for ApplicationCoreBenchmarkVerificationHandoff {
    // Reconstructs one parent receipt entirely from the durable Node handoff and outer request.
    fn prepare(
        &self,
        _job_id: &OperationId,
        request: &BenchmarkRequest,
    ) -> Result<BenchmarkVerificationHandoffReceipt, BenchmarkError> {
        let BenchmarkKind::Verification {
            transaction_id,
            verifier_bundle_sha256,
            ..
        } = request.kind()
        else {
            return Err(BenchmarkError::InvalidContract {
                reason: "candidate handoff requires a verification request",
            });
        };
        let versioned = self
            .coordinator
            .record(transaction_id)
            .map_err(handoff_error)?
            .ok_or(BenchmarkError::NotFound)?;
        let record = versioned.record();
        let candidate_subject = self
            .coordinator
            .prepared_subject(transaction_id)
            .map_err(handoff_error)?;
        if &candidate_subject != request.subject() {
            return Err(BenchmarkError::AuthorizationDenied);
        }
        let baseline_request = BenchmarkRequest::new(
            BenchmarkKind::Local,
            BenchmarkScope::Complete,
            record.baseline().clone(),
        )?;
        BenchmarkVerificationHandoffReceipt::new(
            transaction_id.clone(),
            handoff_receipt_id(record.request_sha256(), verifier_bundle_sha256)?,
            verifier_bundle_sha256.clone(),
            baseline_request,
            request.clone(),
        )
    }

    // Activates the private candidate and returns an endpoint-bound receipt identity.
    fn activate_candidate(
        &self,
        _job_id: &OperationId,
        receipt: &BenchmarkVerificationHandoffReceipt,
    ) -> Result<Sha256Digest, BenchmarkError> {
        let activated = self
            .coordinator
            .activate(receipt.transaction_id())
            .map_err(handoff_error)?;
        if activated.subject() != receipt.candidate_request().subject() {
            return Err(BenchmarkError::AuthorizationDenied);
        }
        derived_digest(
            b"li-core-benchmark-candidate-activation-v1",
            &[
                activated.transaction_id().as_str(),
                activated.subject().runtime_installation_id().as_str(),
                activated.subject().placement_group_id().as_str(),
                activated.subject().execution_sha256().as_str(),
                activated.endpoint().placement_id().as_str(),
                activated.endpoint().node_id().as_str(),
            ],
        )
    }

    // Restores exact baseline intent and returns a phase-bound durable receipt identity.
    fn restore_baseline(
        &self,
        _job_id: &OperationId,
        receipt: &BenchmarkVerificationHandoffReceipt,
    ) -> Result<Sha256Digest, BenchmarkError> {
        let restored = self
            .coordinator
            .restore(receipt.transaction_id())
            .map_err(handoff_error)?;
        let record = restored.record();
        derived_digest(
            b"li-core-benchmark-baseline-restoration-v1",
            &[
                record.transaction_id().as_str(),
                record.request_sha256().as_str(),
                record.baseline_record_sha256().as_str(),
                record.restoration_group_id().as_str(),
            ],
        )
    }

    // Replays Node-owned terminal cleanup without deleting baseline-owned Runtime data.
    fn cleanup(
        &self,
        _job_id: &OperationId,
        receipt: &BenchmarkVerificationHandoffReceipt,
    ) -> Result<(), BenchmarkError> {
        self.coordinator
            .restore(receipt.transaction_id())
            .map(|_| ())
            .map_err(handoff_error)
    }
}

// Converts one preparation-owned closure into the exact RuntimeManager artifact contract.
fn exact_artifacts(
    candidate: &CoreBenchmarkVerificationCandidate,
) -> Result<RuntimeExactCandidateArtifacts, CoreBenchmarkVerificationPreparationError> {
    let engine = match candidate.engine() {
        CoreBenchmarkVerificationEngineArtifact::Reuse => RuntimeExactEngineArtifact::Reuse,
        CoreBenchmarkVerificationEngineArtifact::BuiltOci {
            archive_file,
            config_digest,
            local_tag,
        } => RuntimeExactEngineArtifact::BuiltOci {
            archive_file: archive_file.clone(),
            config_digest: config_digest.clone(),
            local_tag: local_tag.clone(),
        },
        CoreBenchmarkVerificationEngineArtifact::BuiltNative => {
            RuntimeExactEngineArtifact::BuiltNative
        }
    };
    RuntimeExactCandidateArtifacts::new(
        candidate.runtime_pack_file().to_path_buf(),
        engine,
        candidate.bundle_sha256().clone(),
    )
    .map_err(|_| CoreBenchmarkVerificationPreparationError::InvalidAuthority)
}

// Maps Node-owned handoff failures into the parent provider boundary without path detail.
fn handoff_error(_error: li_node_manager::NodeBenchmarkCandidateHandoffError) -> BenchmarkError {
    BenchmarkError::provider("candidate handoff", "candidate handoff failed")
}

// Derives one initial parent handoff receipt from exact Node request and finalizer bundle identities.
fn handoff_receipt_id(
    request_sha256: &Sha256Digest,
    bundle_sha256: &Sha256Digest,
) -> Result<Sha256Digest, BenchmarkError> {
    derived_digest(
        b"li-core-benchmark-handoff-v1",
        &[request_sha256.as_str(), bundle_sha256.as_str()],
    )
}

// Derives one domain-separated digest from exact ordered fields.
fn derived_digest(domain: &[u8], values: &[&str]) -> Result<Sha256Digest, BenchmarkError> {
    let mut digest = Sha256::new();
    digest.update((domain.len() as u64).to_be_bytes());
    digest.update(domain);
    for value in values {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value.as_bytes());
    }
    Sha256Digest::parse(&format!("{:x}", digest.finalize())).map_err(|_| {
        BenchmarkError::InvalidContract {
            reason: "candidate handoff identity could not be derived",
        }
    })
}
