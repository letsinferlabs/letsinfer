// SPDX-License-Identifier: AGPL-3.0-only

use crate::{
    WatchdogError, WatchdogProcessState, WatchdogProtectedEngine, WatchdogProtectionObservation,
    WatchdogProtectionPhase, WatchdogSafetyEvent, WatchdogSample,
};

const MAXIMUM_PROTECTION_CYCLE_TARGETS: usize = 64;

// Carries one armed, untripped process observed during a complete protection cycle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogProtectionLeaseSeed {
    target: WatchdogProtectedEngine,
}

impl WatchdogProtectionLeaseSeed {
    // Returns the exact process, container, boot, and protection-generation binding.
    pub const fn target(&self) -> &WatchdogProtectedEngine {
        &self.target
    }
}

// Proves which protected processes completed one successful Watchdog cycle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogProtectionCycle {
    sample_sequence: u64,
    observed_at_unix_milliseconds: u64,
    observed_at_monotonic_milliseconds: u64,
    targets: Vec<WatchdogProtectionLeaseSeed>,
}

impl WatchdogProtectionCycle {
    // Constructs a receipt only at the successful end of WatchdogManager::tick.
    pub(crate) fn completed(
        sample: &WatchdogSample,
        observations: &[WatchdogProtectionObservation],
        events: &[WatchdogSafetyEvent],
    ) -> Self {
        let targets = observations
            .iter()
            .filter(|observation| {
                observation.target().phase() == WatchdogProtectionPhase::Armed
                    && observation.process_state() == WatchdogProcessState::Running
                    && !observation.trip_latched()
                    && !events.iter().any(|event| {
                        event.generation() == observation.target().generation()
                            && event.action().is_some()
                    })
            })
            .map(|observation| WatchdogProtectionLeaseSeed {
                target: observation.target().clone(),
            })
            .collect();
        Self {
            sample_sequence: sample.sequence(),
            observed_at_unix_milliseconds: sample.unix_milliseconds(),
            observed_at_monotonic_milliseconds: sample.monotonic_milliseconds(),
            targets,
        }
    }

    // Reconstructs one authenticated completed-cycle report at the Node process boundary.
    pub fn from_authenticated_report(
        sample_sequence: u64,
        observed_at_unix_milliseconds: u64,
        observed_at_monotonic_milliseconds: u64,
        targets: Vec<WatchdogProtectedEngine>,
    ) -> Result<Self, WatchdogError> {
        if sample_sequence == 0
            || observed_at_unix_milliseconds == 0
            || observed_at_monotonic_milliseconds == 0
            || targets.len() > MAXIMUM_PROTECTION_CYCLE_TARGETS
            || targets
                .iter()
                .any(|target| target.phase() != WatchdogProtectionPhase::Armed)
        {
            return Err(WatchdogError::InvalidContract {
                reason: "authenticated protection cycle is incomplete or unbounded",
            });
        }
        let mut identities = targets
            .iter()
            .map(protected_engine_identity)
            .collect::<Vec<_>>();
        identities.sort();
        if identities.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(WatchdogError::InvalidContract {
                reason: "authenticated protection cycle contains duplicate targets",
            });
        }
        Ok(Self {
            sample_sequence,
            observed_at_unix_milliseconds,
            observed_at_monotonic_milliseconds,
            targets: targets
                .into_iter()
                .map(|target| WatchdogProtectionLeaseSeed { target })
                .collect(),
        })
    }

    // Returns the exact monotonic Watchdog sample sequence.
    pub const fn sample_sequence(&self) -> u64 {
        self.sample_sequence
    }

    // Returns the host Unix time captured by the completed sample.
    pub const fn observed_at_unix_milliseconds(&self) -> u64 {
        self.observed_at_unix_milliseconds
    }

    // Returns the boot-scoped monotonic time captured by the completed sample.
    pub const fn observed_at_monotonic_milliseconds(&self) -> u64 {
        self.observed_at_monotonic_milliseconds
    }

    // Returns only armed, running, untripped targets from this completed cycle.
    pub fn targets(&self) -> &[WatchdogProtectionLeaseSeed] {
        &self.targets
    }
}

// Returns one deterministic exact-process identity for duplicate rejection.
fn protected_engine_identity(target: &WatchdogProtectedEngine) -> String {
    format!(
        "{}\0{}\0{}\0{}\0{}\0{}\0{}",
        target.generation(),
        target.container_name(),
        target.container_id().unwrap_or_default(),
        target.process_id().unwrap_or_default(),
        target.process_start_ticks().unwrap_or_default(),
        target.boot_id().unwrap_or_default(),
        target.cgroup().unwrap_or_default(),
    )
}
