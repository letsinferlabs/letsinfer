// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use li_node_manager::{
    NodeCatalogApiError, NodeCatalogApiPort, NodeCatalogAuthor, NodeCatalogAuthorKind,
    NodeCatalogEntry, NodeCatalogListRequest, NodeCatalogListing, NodeCatalogRefreshPolicy,
    NodeCatalogSnapshot, NodeCatalogTarget, NodeCatalogTargetSelection,
    NodeCatalogVersionSelection, NodeManager,
};
use li_runtime_manager::{
    RuntimeCatalogAuthorKind, RuntimeCatalogListing, RuntimeCatalogLoadOptions, RuntimeError,
    SignedRuntimeCatalogProvider,
};

// Adapts NodeManager hardware state and RuntimeManager catalog judgment into one Node projection.
pub struct CoreNodeCatalogApi {
    nodes: Arc<NodeManager>,
    catalog: Arc<SignedRuntimeCatalogProvider>,
}

impl CoreNodeCatalogApi {
    // Creates one explicit cross-manager adapter without copying either manager's state.
    pub const fn new(nodes: Arc<NodeManager>, catalog: Arc<SignedRuntimeCatalogProvider>) -> Self {
        Self { nodes, catalog }
    }
}

impl NodeCatalogApiPort for CoreNodeCatalogApi {
    // Uses only the configured signed provider and local durable hardware observation.
    fn list(
        &self,
        request: &NodeCatalogListRequest,
    ) -> Result<NodeCatalogListing, NodeCatalogApiError> {
        validate_catalog_source(request, self.catalog.source())?;
        let hardware = match request.targets() {
            NodeCatalogTargetSelection::Compatible => Some(
                self.nodes
                    .hardware_observation(self.nodes.local_node_id())
                    .map_err(|_| NodeCatalogApiError::Unavailable)?
                    .ok_or(NodeCatalogApiError::Unavailable)?,
            ),
            NodeCatalogTargetSelection::All => None,
        };
        let options = catalog_load_options(request.refresh());
        let listing = self
            .catalog
            .list_with_options(
                request.logical_model(),
                hardware.as_ref(),
                request.versions() == NodeCatalogVersionSelection::All,
                request.targets() == NodeCatalogTargetSelection::All,
                options,
            )
            .map_err(node_catalog_error)?;
        node_catalog_listing(listing)
    }

    // Uses the configured signed catalog and exact durable hardware snapshot for one node.
    fn compatible_targets(
        &self,
        node_id: &li_core_interface::NodeId,
        catalog_source: &str,
    ) -> Result<Vec<NodeCatalogTarget>, NodeCatalogApiError> {
        if catalog_source != self.catalog.source() {
            return Err(NodeCatalogApiError::InvalidRequest);
        }
        self.nodes
            .node(node_id)
            .map_err(|_| NodeCatalogApiError::Unavailable)?;
        let hardware = self
            .nodes
            .hardware_observation(node_id)
            .map_err(|_| NodeCatalogApiError::Unavailable)?
            .ok_or(NodeCatalogApiError::Unavailable)?;
        let entries = self
            .catalog
            .list(None, Some(&hardware), false, false)
            .map_err(node_catalog_error)?;
        let mut targets = entries
            .into_iter()
            .map(|entry| {
                NodeCatalogTarget::new(
                    entry.logical_model().clone(),
                    entry.target().id().clone(),
                    entry.candidate_id().clone(),
                    entry.is_recommended(),
                )
            })
            .collect::<Vec<_>>();
        targets.sort_by(|left, right| {
            (
                left.logical_model().as_str(),
                left.target_id().as_str(),
                left.candidate_id().as_str(),
            )
                .cmp(&(
                    right.logical_model().as_str(),
                    right.target_id().as_str(),
                    right.candidate_id().as_str(),
                ))
        });
        if targets.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(NodeCatalogApiError::InvalidResponse);
        }
        Ok(targets)
    }
}

// Requires an optional caller source to match the configured signed provider byte for byte.
fn validate_catalog_source(
    request: &NodeCatalogListRequest,
    configured_source: &str,
) -> Result<(), NodeCatalogApiError> {
    if request
        .catalog_source()
        .is_some_and(|source| source != configured_source)
    {
        return Err(NodeCatalogApiError::InvalidRequest);
    }
    Ok(())
}

// Maps the closed Node freshness selection to ordinary or strict signed-provider loading.
const fn catalog_load_options(policy: NodeCatalogRefreshPolicy) -> RuntimeCatalogLoadOptions {
    match policy {
        NodeCatalogRefreshPolicy::Cached => RuntimeCatalogLoadOptions::ordinary(),
        NodeCatalogRefreshPolicy::Refresh => RuntimeCatalogLoadOptions::refresh(false),
    }
}

// Projects one verified RuntimeManager listing into the closed Node private contract.
fn node_catalog_listing(
    listing: RuntimeCatalogListing,
) -> Result<NodeCatalogListing, NodeCatalogApiError> {
    let snapshot = listing.snapshot();
    let snapshot = NodeCatalogSnapshot::new(
        snapshot.source().to_string(),
        snapshot.catalog_sha256().clone(),
        snapshot.revocations_sha256().clone(),
        snapshot.revocation_sequence(),
        snapshot.verified_at_unix(),
        snapshot.is_stale(),
    )?;
    let entries = listing
        .entries()
        .iter()
        .map(|entry| {
            let authors = entry
                .authors()
                .iter()
                .map(|author| {
                    NodeCatalogAuthor::new(
                        author.github_login().to_string(),
                        author.github_id(),
                        match author.github_type() {
                            RuntimeCatalogAuthorKind::User => NodeCatalogAuthorKind::User,
                            RuntimeCatalogAuthorKind::Organization => {
                                NodeCatalogAuthorKind::Organization
                            }
                        },
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            NodeCatalogEntry::new(
                entry.logical_model().clone(),
                entry.target().id().clone(),
                entry.candidate_id().clone(),
                entry.version().to_string(),
                entry.source().as_str().to_string(),
                entry.engine().clone(),
                entry.model_uri().to_string(),
                authors,
                entry.license().to_string(),
                entry.evidence_label(),
                entry.verification_method().to_string(),
                entry.benchmark_score(),
                entry.is_recommended(),
            )
        })
        .collect::<Result<Vec<_>, NodeCatalogApiError>>()?;
    NodeCatalogListing::new(snapshot, entries)
}

// Maps signed-catalog failures into the narrow Node projection boundary.
fn node_catalog_error(error: RuntimeError) -> NodeCatalogApiError {
    match error {
        RuntimeError::CatalogUnavailable
        | RuntimeError::CatalogTrustUnavailable
        | RuntimeError::CatalogCacheUnavailable
        | RuntimeError::DownloadUnavailable => NodeCatalogApiError::Unavailable,
        _ => NodeCatalogApiError::InvalidResponse,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Returns one deterministic request for source and refresh-policy adapter tests.
    fn request(source: Option<&str>, refresh: NodeCatalogRefreshPolicy) -> NodeCatalogListRequest {
        NodeCatalogListRequest::new(
            source.map(str::to_string),
            None,
            NodeCatalogVersionSelection::Latest,
            NodeCatalogTargetSelection::Compatible,
            refresh,
        )
        .expect("request")
    }

    // Accepts only the configured signed source and never an alternate caller location.
    #[test]
    fn catalog_source_assertion_matches_exact_configured_identity() {
        let configured = "https://catalog.letsinfer.ai/catalog.json";
        assert_eq!(
            validate_catalog_source(
                &request(Some(configured), NodeCatalogRefreshPolicy::Cached),
                configured,
            ),
            Ok(())
        );
        assert_eq!(
            validate_catalog_source(
                &request(
                    Some("https://alternate.example/catalog.json"),
                    NodeCatalogRefreshPolicy::Cached,
                ),
                configured,
            ),
            Err(NodeCatalogApiError::InvalidRequest)
        );
    }

    // Preserves ordinary stale fallback while making explicit refresh strictly fresh.
    #[test]
    fn catalog_refresh_selection_maps_to_exact_signed_provider_policy() {
        assert_eq!(
            catalog_load_options(NodeCatalogRefreshPolicy::Cached),
            RuntimeCatalogLoadOptions::ordinary()
        );
        assert_eq!(
            catalog_load_options(NodeCatalogRefreshPolicy::Refresh),
            RuntimeCatalogLoadOptions::refresh(false)
        );
    }
}
