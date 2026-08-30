// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use li_benchmark_manager::{
    BenchmarkError, BenchmarkKind, BenchmarkRequest, BenchmarkScope, BenchmarkSubject,
};
use li_core_interface::{ModelServiceDesiredState, RuntimeInstallationState, TechnicalName};
use li_node_manager::{
    NodeBenchmarkContext, NodeBenchmarkPlan, NodeBenchmarkRequestProvider, NodeBenchmarkSelection,
    NodeManager,
};
use li_placement_manager::PlacementStore;
use li_runtime_manager::{RuntimeInstallationStore, RuntimeManager};

// Resolves public local benchmark selections through exact manager-owned identities.
pub struct ApplicationBenchmarkRequestProvider {
    node: Arc<NodeManager>,
    runtime: Arc<RuntimeManager>,
    runtime_store: Arc<dyn RuntimeInstallationStore>,
    placement_store: Arc<dyn PlacementStore>,
}

impl ApplicationBenchmarkRequestProvider {
    // Creates one resolver from existing Node, Runtime, and Placement read capabilities.
    pub const fn new(
        node: Arc<NodeManager>,
        runtime: Arc<RuntimeManager>,
        runtime_store: Arc<dyn RuntimeInstallationStore>,
        placement_store: Arc<dyn PlacementStore>,
    ) -> Self {
        Self {
            node,
            runtime,
            runtime_store,
            placement_store,
        }
    }
}

impl NodeBenchmarkRequestProvider for ApplicationBenchmarkRequestProvider {
    // Re-resolves one model and workload selection without mutating any manager state.
    fn resolve(
        &self,
        selection: &NodeBenchmarkSelection,
    ) -> Result<NodeBenchmarkPlan, BenchmarkError> {
        let local_node = self
            .node
            .local_node()
            .map_err(|_| request_error("local Core installation is unavailable"))?;
        let services = self
            .node
            .model_services()
            .map_err(|_| request_error("installed model state is unavailable"))?;
        let mut matching_services = services.iter().filter(|service| {
            service.logical_model() == selection.logical_model()
                && service.desired_state() != ModelServiceDesiredState::Removed
        });
        let service = matching_services
            .next()
            .ok_or_else(|| request_error("installed model is unavailable"))?;
        if matching_services.next().is_some() {
            return Err(request_error("installed model state is ambiguous"));
        }
        let placement_group_id = service
            .placement_group_ids()
            .first()
            .ok_or_else(|| request_error("installed model has no placement group"))?;
        let placement_record = self
            .placement_store
            .read(placement_group_id)
            .map_err(|_| request_error("placement group is unavailable"))?
            .ok_or_else(|| request_error("placement group is unavailable"))?;
        let placement_record = placement_record.record();
        if placement_record.group().service_id() != service.service_id() {
            return Err(request_error("placement group ownership is inconsistent"));
        }
        let placement = placement_record
            .placements()
            .first()
            .ok_or_else(|| request_error("placement group has no runtime assignment"))?;
        let runtime_installation_id = placement.assignment().runtime_installation_id();
        let runtime_installation = self
            .runtime_store
            .read(runtime_installation_id)
            .map_err(|_| request_error("runtime installation is unavailable"))?
            .ok_or_else(|| request_error("runtime installation is unavailable"))?;
        let runtime_installation = runtime_installation.installation();
        if runtime_installation.state() != RuntimeInstallationState::Available
            || runtime_installation.node_id() != placement.assignment().node_id()
            || runtime_installation.logical_model() != selection.logical_model()
            || runtime_installation.runtime() != placement_record.group().runtime()
        {
            return Err(request_error(
                "runtime installation identity is inconsistent",
            ));
        }
        let manifest = self
            .runtime
            .execution_manifest(runtime_installation_id)
            .map_err(|_| request_error("runtime execution manifest is unavailable"))?;
        if manifest.installation_id() != runtime_installation_id
            || manifest.logical_model() != selection.logical_model()
        {
            return Err(request_error(
                "runtime execution manifest identity is inconsistent",
            ));
        }
        let benchmark = manifest
            .benchmark()
            .ok_or_else(|| request_error("runtime benchmark contract is unsupported"))?;
        let declared_cells = benchmark.declared_cells().to_vec();
        let selected_cells = selected_benchmark_cells(selection, &declared_cells)?;
        let scope = if selected_cells == declared_cells {
            BenchmarkScope::Complete
        } else {
            BenchmarkScope::selected(selected_cells.clone())?
        };
        let request = BenchmarkRequest::new(
            BenchmarkKind::Local,
            scope,
            BenchmarkSubject::new(
                local_node.identity().installation_id().clone(),
                runtime_installation_id.clone(),
                selection.logical_model().clone(),
                placement_group_id.clone(),
                runtime_installation
                    .runtime()
                    .execution_contract_digest()
                    .clone(),
                benchmark.contract_sha256().clone(),
                benchmark.target_contract_sha256().clone(),
            ),
        )?;
        NodeBenchmarkPlan::new(selection, request, declared_cells, selected_cells)
    }
}

// Describes the public axes encoded by one signed benchmark cell identity.
#[derive(Clone, Copy)]
struct BenchmarkCellAxes {
    context: Option<NodeBenchmarkContext>,
    concurrency: u16,
}

// Preserves signed cell order while applying the requested context and concurrency cross-product.
fn selected_benchmark_cells(
    selection: &NodeBenchmarkSelection,
    declared_cells: &[TechnicalName],
) -> Result<Vec<TechnicalName>, BenchmarkError> {
    let mut selected = Vec::new();
    for cell in declared_cells {
        let axes = benchmark_cell_axes(cell)?;
        let context_matches = selection.contexts().is_empty()
            || axes
                .context
                .is_some_and(|context| selection.contexts().contains(&context));
        let concurrency_matches = selection.concurrencies().is_empty()
            || selection.concurrencies().contains(&axes.concurrency);
        if context_matches && concurrency_matches {
            selected.push(cell.clone());
        }
    }
    if selected.is_empty() {
        return Err(request_error("benchmark workload selection is empty"));
    }
    Ok(selected)
}

// Parses only the closed schema-8 cell vocabulary already verified by RuntimeManager.
fn benchmark_cell_axes(cell: &TechnicalName) -> Result<BenchmarkCellAxes, BenchmarkError> {
    let parts = cell.as_str().split('-').collect::<Vec<_>>();
    if parts.len() != 3 || !matches!(parts[1], "code" | "prose") {
        return Err(request_error("runtime benchmark cell identity is invalid"));
    }
    let concurrency = parts[2]
        .strip_prefix('c')
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|value| matches!(value, 1 | 2 | 4 | 8 | 16))
        .ok_or_else(|| request_error("runtime benchmark cell identity is invalid"))?;
    let context = match parts[0] {
        "short" => None,
        "32k" => Some(NodeBenchmarkContext::Context32k),
        "64k" => Some(NodeBenchmarkContext::Context64k),
        "128k" => Some(NodeBenchmarkContext::Context128k),
        "256k" => Some(NodeBenchmarkContext::Context256k),
        "ttftcold" | "ttftwarm" if parts[1] == "code" && concurrency == 1 => None,
        _ => return Err(request_error("runtime benchmark cell identity is invalid")),
    };
    Ok(BenchmarkCellAxes {
        context,
        concurrency,
    })
}

// Returns one stable redacted selection boundary failure.
fn request_error(reason: &'static str) -> BenchmarkError {
    BenchmarkError::provider("selection", reason)
}
