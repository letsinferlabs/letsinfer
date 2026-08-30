// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use li_core_update_manager::{CoreUpdateServiceContext, CoreUpdateServicePlatform};

use crate::{
    CoreResidentProcess, CoreServiceSetupError, CoreServiceSetupObservation,
    CoreServiceSetupResidentHealth,
};

// Routes every required resident to exactly one process-owned health implementation.
pub struct CoreServiceSetupResidentHealthRouter {
    platform: CoreUpdateServicePlatform,
    residents: BTreeMap<CoreResidentProcess, Arc<dyn CoreServiceSetupResidentHealth>>,
}

impl CoreServiceSetupResidentHealthRouter {
    // Creates one closed platform service set without missing, duplicate, or foreign roles.
    pub fn new(
        platform: CoreUpdateServicePlatform,
        residents: Vec<(CoreResidentProcess, Arc<dyn CoreServiceSetupResidentHealth>)>,
    ) -> Result<Self, CoreServiceSetupError> {
        let expected = expected_residents(platform);
        let mut routed = BTreeMap::new();
        for (process, resident) in residents {
            if !expected.contains(&process) || routed.insert(process, resident).is_some() {
                return Err(router_error("resident health service set is ambiguous"));
            }
        }
        if routed.keys().copied().collect::<BTreeSet<_>>() != expected {
            return Err(router_error("resident health service set is incomplete"));
        }
        Ok(Self {
            platform,
            residents: routed,
        })
    }
}

impl CoreServiceSetupResidentHealth for CoreServiceSetupResidentHealthRouter {
    // Delegates one role exactly once while preserving its context, timeout, and outcome.
    fn observe(
        &self,
        context: CoreUpdateServiceContext,
        process: CoreResidentProcess,
        timeout: Duration,
    ) -> Result<CoreServiceSetupObservation, CoreServiceSetupError> {
        if context.platform() != self.platform || timeout.is_zero() {
            return Err(router_error("resident health request is invalid"));
        }
        self.residents
            .get(&process)
            .ok_or_else(|| router_error("resident health role is unavailable"))?
            .observe(context, process, timeout)
    }
}

// Returns the complete independently supervised resident set for one native platform.
fn expected_residents(platform: CoreUpdateServicePlatform) -> BTreeSet<CoreResidentProcess> {
    let mut residents = BTreeSet::from([CoreResidentProcess::Node, CoreResidentProcess::Gateway]);
    if platform == CoreUpdateServicePlatform::Linux {
        residents.insert(CoreResidentProcess::Watchdog);
    }
    residents
}

// Creates one stable service-health composition failure without provider detail.
const fn router_error(reason: &'static str) -> CoreServiceSetupError {
    CoreServiceSetupError::InvalidContract { reason }
}
