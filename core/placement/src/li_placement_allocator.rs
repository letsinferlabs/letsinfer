// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;

use li_core_interface::{
    EndpointOwnership, EntityTimestamps, ModelServiceDesiredState, NetworkPort, Placement,
    PlacementAssignment, PlacementGroup, PlacementGroupState, PlacementId, PlacementState,
    PortRange, ResourceIdentity, ResourceLease, ResourceLeaseState,
};

use crate::{
    placement_resources, PlacementAdmissionPolicy, PlacementClock, PlacementError,
    PlacementIdentityProvider, PlacementRecord, PlacementRequest, PlacementStore,
    VersionedPlacementRecord,
};

// Allocates every exact resource and commits one atomic staging aggregate.
pub(crate) fn allocate(
    request: &PlacementRequest,
    store: &dyn PlacementStore,
    identity: &dyn PlacementIdentityProvider,
    clock: &dyn PlacementClock,
    admission: PlacementAdmissionPolicy,
) -> Result<VersionedPlacementRecord, PlacementError> {
    let observed_at = clock.now()?;
    admission.validate(request.nodes(), observed_at)?;
    let placement_group_id = request.placement_group_id().clone();
    let node_order = bound_node_order(request)?;
    let mut placements = Vec::with_capacity(request.tasks().len());
    let mut leases = Vec::new();
    let mut placement_by_task = HashMap::new();
    for (task, node_index) in request.tasks().iter().zip(node_order) {
        let node = &request.nodes()[node_index];
        let occupied = store.occupied_resources(node.node_id())?;
        let device_ids = available_devices(node.device_ids(), task.device_count(), &occupied)?;
        let ports = available_ports(node.ports(), task.port_count(), &occupied)?;
        let rdma_interface = if request.capacity().interconnect().rdma_required() {
            let interface = node
                .rdma_interface()
                .ok_or(PlacementError::TopologyUnavailable)?;
            let resource = ResourceIdentity::RdmaInterface(interface.clone());
            if is_occupied(&resource, &occupied) {
                return Err(PlacementError::ResourceUnavailable);
            }
            Some(interface.clone())
        } else {
            None
        };
        let placement_id = identity.placement_id(task.task_id())?;
        let resources = placement_resources(ports, device_ids, rdma_interface)?;
        let endpoint_ownership = if task.task_id() == request.endpoint_task_id() {
            EndpointOwnership::Owner
        } else {
            EndpointOwnership::Participant
        };
        let placement = Placement::new(
            placement_id.clone(),
            placement_group_id.clone(),
            PlacementAssignment::new(
                node.node_id().clone(),
                node.runtime_installation_id().clone(),
                node.hardware_observation_id().clone(),
                node.boot_id().clone(),
                node.observed_at(),
                task.task_id().clone(),
                node.address().clone(),
                resources,
                endpoint_ownership,
            ),
            PlacementState::Staging,
            None,
            None,
            EntityTimestamps::new(observed_at, observed_at)
                .map_err(|_| PlacementError::ClockUnavailable)?,
        )
        .map_err(|_| PlacementError::InvalidRequest {
            reason: "allocated placement is invalid",
        })?;
        for resource in placement_resource_identities(&placement) {
            leases.push(ResourceLease::new(
                identity.resource_lease_id(&placement_id, &resource)?,
                placement_id.clone(),
                node.node_id().clone(),
                resource,
                ResourceLeaseState::Reserved,
                EntityTimestamps::new(observed_at, observed_at)
                    .map_err(|_| PlacementError::ClockUnavailable)?,
            ));
        }
        placement_by_task.insert(task.task_id().clone(), placement_id);
        placements.push(placement);
    }
    let placement_ids: Vec<PlacementId> = placements
        .iter()
        .map(|placement| placement.placement_id().clone())
        .collect();
    let endpoint_placement_id = placement_by_task
        .get(request.endpoint_task_id())
        .cloned()
        .ok_or(PlacementError::InvalidRequest {
            reason: "endpoint placement is unavailable",
        })?;
    let startup_order = request
        .startup_order()
        .iter()
        .map(|phase| {
            phase
                .iter()
                .map(|task_id| {
                    placement_by_task
                        .get(task_id)
                        .cloned()
                        .ok_or(PlacementError::InvalidRequest {
                            reason: "startup task has no placement",
                        })
                })
                .collect()
        })
        .collect::<Result<Vec<Vec<PlacementId>>, PlacementError>>()?;
    let group = PlacementGroup::new(
        placement_group_id,
        request.service_id().clone(),
        request.runtime().clone(),
        placement_ids,
        endpoint_placement_id,
        None,
        request.capacity(),
        ModelServiceDesiredState::Running,
        PlacementGroupState::Staging,
        None,
        EntityTimestamps::new(observed_at, observed_at)
            .map_err(|_| PlacementError::ClockUnavailable)?,
    )
    .map_err(|_| PlacementError::InvalidRequest {
        reason: "allocated placement group is invalid",
    })?;
    store.create(PlacementRecord::new(
        group,
        placements,
        leases,
        startup_order,
        Vec::new(),
    )?)
}

// Maps the endpoint-owner task to the selected endpoint node deterministically.
pub(crate) fn bound_node_order(request: &PlacementRequest) -> Result<Vec<usize>, PlacementError> {
    let endpoint_task_index = request
        .tasks()
        .iter()
        .position(|task| task.task_id() == request.endpoint_task_id())
        .ok_or(PlacementError::InvalidRequest {
            reason: "endpoint task is unavailable",
        })?;
    let endpoint_node_index = request
        .nodes()
        .iter()
        .position(|node| node.node_id() == request.endpoint_node_id())
        .ok_or(PlacementError::InvalidRequest {
            reason: "endpoint node is unavailable",
        })?;
    let mut order: Vec<usize> = (0..request.nodes().len()).collect();
    order.swap(endpoint_task_index, endpoint_node_index);
    Ok(order)
}

// Chooses the lowest stable unoccupied accelerator identities.
fn available_devices(
    candidates: &[li_core_interface::DeviceId],
    count: u16,
    occupied: &[ResourceIdentity],
) -> Result<Vec<li_core_interface::DeviceId>, PlacementError> {
    let mut available: Vec<li_core_interface::DeviceId> = candidates
        .iter()
        .filter(|device_id| {
            !is_occupied(
                &ResourceIdentity::Accelerator((*device_id).clone()),
                occupied,
            )
        })
        .cloned()
        .collect();
    available.sort();
    available.truncate(usize::from(count));
    if available.len() != usize::from(count) {
        return Err(PlacementError::ResourceUnavailable);
    }
    Ok(available)
}

// Chooses the lowest contiguous unoccupied port range.
fn available_ports(
    candidates: PortRange,
    count: u16,
    occupied: &[ResourceIdentity],
) -> Result<PortRange, PlacementError> {
    if count > candidates.count() {
        return Err(PlacementError::ResourceUnavailable);
    }
    let final_base = candidates.last() - count + 1;
    for base in candidates.base()..=final_base {
        let is_available = (0..count).all(|offset| {
            let port = NetworkPort::new(base + offset).expect("validated managed port");
            !is_occupied(&ResourceIdentity::Port(port), occupied)
        });
        if is_available {
            return PortRange::new(base, count).map_err(|_| PlacementError::ResourceUnavailable);
        }
    }
    Err(PlacementError::ResourceUnavailable)
}

// Returns every exact resource represented by one placement assignment.
fn placement_resource_identities(placement: &Placement) -> Vec<ResourceIdentity> {
    let resources = placement.assignment().resources();
    let mut identities: Vec<ResourceIdentity> = resources
        .device_ids()
        .iter()
        .cloned()
        .map(ResourceIdentity::Accelerator)
        .collect();
    let ports = resources.ports();
    identities.extend((0..ports.count()).map(|offset| {
        ResourceIdentity::Port(
            NetworkPort::new(ports.base() + offset).expect("validated managed port"),
        )
    }));
    if let Some(interface) = resources.rdma_interface() {
        identities.push(ResourceIdentity::RdmaInterface(interface.clone()));
    }
    identities
}

// Returns whether one exact resource is already leased.
fn is_occupied(resource: &ResourceIdentity, occupied: &[ResourceIdentity]) -> bool {
    occupied.iter().any(|candidate| candidate == resource)
}
