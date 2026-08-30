// SPDX-License-Identifier: AGPL-3.0-only

mod li_watchdog_configuration;
mod li_watchdog_contract;
mod li_watchdog_controller_registry;
mod li_watchdog_controller_snapshot;
mod li_watchdog_event_journal;
mod li_watchdog_gateway_telemetry;
mod li_watchdog_linux_process;
mod li_watchdog_linux_protection;
mod li_watchdog_linux_sampler;
mod li_watchdog_live_fanout;
mod li_watchdog_native_io;
mod li_watchdog_nvml;
mod li_watchdog_protection_cycle;
mod li_watchdog_protocol_health;
mod li_watchdog_protocol_identity;
mod li_watchdog_protocol_listener;
mod li_watchdog_protocol_v3;
mod li_watchdog_record;
mod li_watchdog_resident;
mod li_watchdog_ring;
mod li_watchdog_rollup;
mod li_watchdog_rustls_tcp;
mod li_watchdog_storage;

pub use li_watchdog_configuration::{
    SystemWatchdogConfigurationFileProvider, WatchdogConfiguration, WatchdogConfigurationFile,
    WatchdogConfigurationFileProvider, WatchdogConfigurationLoader,
    WatchdogGatewayCounterProviderKind, WatchdogGpuProviderKind,
    WatchdogNodeProtectionConfiguration, WATCHDOG_CONFIGURATION_MAX_BYTES,
    WATCHDOG_CONFIGURATION_SCHEMA, WATCHDOG_CONFIGURATION_VERSION,
};
pub use li_watchdog_contract::{
    maximum_watchdog_targets, WatchdogError, WatchdogProcessState, WatchdogProtectedEngine,
    WatchdogProtectionObservation, WatchdogProtectionPhase, WatchdogSafetyAction,
    WatchdogSafetyEvent, WatchdogSafetyInput, WatchdogSafetyThresholds, WatchdogSample,
    WatchdogSampleTelemetry, WatchdogTick, WATCHDOG_CLOCK_UNKNOWN, WATCHDOG_GPU_ENGINES,
    WATCHDOG_MAX_CPU_CORES, WATCHDOG_PERCENT_UNKNOWN, WATCHDOG_SAMPLE_GATEWAY_AVAILABLE,
    WATCHDOG_SAMPLE_GPU_AVAILABLE, WATCHDOG_SAMPLE_ROLLUP, WATCHDOG_SAMPLE_THROTTLED,
    WATCHDOG_TEMP_UNKNOWN,
};
pub use li_watchdog_controller_registry::{
    WatchdogControllerAllowlist, WatchdogControllerBinding, WatchdogControllerMutation,
    WatchdogControllerMutationKind, WatchdogControllerRegistry, WatchdogControllerRegistryStore,
    WatchdogControllerSnapshotProvider,
};
pub use li_watchdog_controller_snapshot::{
    FilesystemWatchdogControllerSnapshotProvider, SystemWatchdogControllerSnapshotIo,
    WatchdogControllerSnapshotFile, WatchdogControllerSnapshotIo,
};
pub(crate) use li_watchdog_event_journal::WatchdogEventJournal;
pub use li_watchdog_gateway_telemetry::{
    SystemWatchdogGatewayTelemetryFileProvider, UnsupportedWatchdogGatewayTelemetryProvider,
    WatchdogGatewayTelemetry, WatchdogGatewayTelemetryFile, WatchdogGatewayTelemetryFileProvider,
    WatchdogGatewayTelemetryProvider, WatchdogGatewayTelemetrySampleProvider,
};
pub use li_watchdog_linux_process::{
    SystemWatchdogLinuxPidFdProvider, SystemWatchdogLinuxProcessProvider, WatchdogLinuxPidFd,
    WatchdogLinuxPidFdProvider, WatchdogLinuxProcessLayout, WatchdogLinuxProcessProvider,
    WatchdogLinuxSignal,
};
pub use li_watchdog_linux_protection::{
    LinuxWatchdogProtectionProvider, SystemWatchdogLinuxProtectionFileProvider,
    WatchdogLinuxProtectionFileProvider, WatchdogLinuxProtectionLayout,
};
pub use li_watchdog_linux_sampler::{
    LinuxWatchdogSampleProvider, SystemWatchdogLinuxClock, SystemWatchdogLinuxHostFileProvider,
    UnsupportedWatchdogLinuxGpuProvider, WatchdogLinuxCapability, WatchdogLinuxClock,
    WatchdogLinuxClocks, WatchdogLinuxFilesystemUsage, WatchdogLinuxGpuProvider,
    WatchdogLinuxGpuSample, WatchdogLinuxHostFileProvider, WatchdogLinuxSampleLayout,
};
pub use li_watchdog_live_fanout::{
    SystemWatchdogLiveClock, SystemWatchdogLiveWake, WatchdogLiveClock, WatchdogLiveDrain,
    WatchdogLiveDrainState, WatchdogLiveFanout, WatchdogLiveFanoutLimits, WatchdogLivePublish,
    WatchdogLivePublishKind, WatchdogLiveReceiver, WatchdogLiveRunControl, WatchdogLiveSink,
    WatchdogLiveWake,
};
pub use li_watchdog_nvml::{
    validate_watchdog_nvml_symbol_contract, DynamicWatchdogNvmlPort, NvmlWatchdogLinuxGpuProvider,
    WatchdogNvmlDeviceSample, WatchdogNvmlPort, WatchdogNvmlSymbolProvider,
};
pub use li_watchdog_protection_cycle::{WatchdogProtectionCycle, WatchdogProtectionLeaseSeed};
pub use li_watchdog_protocol_health::{
    WatchdogProtocolResidentLifecycle, WatchdogProtocolResidentStatus,
};
pub use li_watchdog_protocol_identity::{
    FilesystemWatchdogProtocolIdentityProvider, SystemWatchdogPublicStateFileProvider,
    WatchdogProtocolRuntimeStatus, WatchdogProtocolRuntimeStatusProvider, WatchdogPublicStateFile,
    WatchdogPublicStateFileProvider, WATCHDOG_PUBLIC_STATE_MAX_BYTES,
};
pub use li_watchdog_protocol_listener::{
    FilesystemWatchdogProtocolDataProvider, WatchdogAuthenticatedStream,
    WatchdogControllerSessionProvider, WatchdogProtocolConnectionOutcome,
    WatchdogProtocolDataError, WatchdogProtocolDataProvider, WatchdogProtocolDispatchResult,
    WatchdogProtocolDispatcher, WatchdogProtocolHistoryCursor, WatchdogProtocolIdentityProvider,
    WatchdogProtocolListener, WatchdogProtocolListenerLimits, WatchdogProtocolResponseSink,
    WatchdogProtocolService, WatchdogProtocolSubscription,
    WATCHDOG_PROTOCOL_IDLE_TIMEOUT_MILLISECONDS, WATCHDOG_PROTOCOL_MAX_CONNECTIONS,
    WATCHDOG_PROTOCOL_MAX_REQUESTS_PER_CONNECTION,
};
pub use li_watchdog_protocol_v3::{
    decode_watchdog_protocol_frame, decode_watchdog_protocol_request,
    decode_watchdog_protocol_response, encode_watchdog_protocol_frame,
    encode_watchdog_protocol_request, encode_watchdog_protocol_response,
    WatchdogProtocolCapabilities, WatchdogProtocolRequest, WatchdogProtocolRequestKind,
    WatchdogProtocolResolution, WatchdogProtocolResponse, WatchdogProtocolResponseKind,
    WatchdogProtocolSiteStatus, WATCHDOG_PROTOCOL_MAX_BATCH_SAMPLES,
    WATCHDOG_PROTOCOL_MAX_FRAME_BYTES, WATCHDOG_PROTOCOL_VERSION,
};
pub use li_watchdog_record::{
    decode_watchdog_record, encode_watchdog_record, watchdog_crc32, WATCHDOG_RECORD_BYTES,
};
pub use li_watchdog_resident::{
    SystemWatchdogControllerAllowlistSource, SystemWatchdogResidentSignalAdapter,
    SystemWatchdogResidentSignalState, WatchdogControllerAllowlistSource,
    WatchdogControllerRegistryReloader, WatchdogResident, WatchdogResidentClock,
    WatchdogResidentConfigurationSource, WatchdogResidentOutcome, WatchdogResidentProtocolService,
    WatchdogResidentService, WatchdogResidentSignalSource, WatchdogResidentSignals,
    WatchdogResidentWake, WatchdogResidentWakeReason,
};
pub use li_watchdog_ring::{
    WatchdogRing, WatchdogRingFile, WatchdogRingHistory, WatchdogRingLayout,
};
pub use li_watchdog_rollup::WatchdogRollup;
pub use li_watchdog_rustls_tcp::{
    SystemWatchdogTlsFileProvider, WatchdogRustlsServerConfiguration, WatchdogRustlsTcpLimits,
    WatchdogRustlsTcpServer, WatchdogTlsFile, WatchdogTlsFileProvider, WatchdogTlsFileSet,
};
pub use li_watchdog_storage::{
    FilesystemWatchdogStorage, WatchdogResolution, WatchdogStorageLayout,
};

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

// Produces one complete model-neutral host sample for an exact sequence.
pub trait WatchdogSampleProvider: Send + Sync {
    // Returns the next host sample without persisting or judging it.
    fn sample(&self, sequence: u64) -> Result<WatchdogSample, WatchdogError>;
}

// Observes and contains exact protected placement processes.
pub trait WatchdogProtectionProvider: Send + Sync {
    // Returns every current protected target and its live kernel observation.
    fn observations(
        &self,
        sample: &WatchdogSample,
    ) -> Result<Vec<WatchdogProtectionObservation>, WatchdogError>;

    // Acknowledges one disarmed generation before its owner exits deliberately.
    fn acknowledge_disarmed(&self, target: &WatchdogProtectedEngine) -> Result<(), WatchdogError>;

    // Writes one durable trip latch before any containment signal is sent.
    fn latch_trip(
        &self,
        target: &WatchdogProtectedEngine,
        action: WatchdogSafetyAction,
        reason: &'static str,
        input: WatchdogSafetyInput,
    ) -> Result<(), WatchdogError>;

    // Contains the exact pidfd and cgroup and reports whether they became empty.
    fn contain(
        &self,
        target: &WatchdogProtectedEngine,
        action: WatchdogSafetyAction,
        grace_milliseconds: u32,
    ) -> Result<bool, WatchdogError>;
}

// Persists Watchdog samples and safety events under explicit crash boundaries.
pub trait WatchdogStorageProvider: Send + Sync {
    // Returns the next sequence after the complete durable ring head.
    fn next_sequence(&self) -> Result<u64, WatchdogError>;

    // Records one sample idempotently by sequence.
    fn record_sample(&self, sample: &WatchdogSample) -> Result<(), WatchdogError>;

    // Records one closed safety event idempotently by generation, kind, and sequence.
    fn record_event(&self, event: &WatchdogSafetyEvent) -> Result<(), WatchdogError>;

    // Flushes every recorded sample and event before or after containment.
    fn flush(&self) -> Result<(), WatchdogError>;
}

// Owns resident sampling, safety decisions, containment ordering, and sequence state.
pub struct WatchdogManager {
    thresholds: WatchdogSafetyThresholds,
    samples: Arc<dyn WatchdogSampleProvider>,
    protection: Arc<dyn WatchdogProtectionProvider>,
    storage: Arc<dyn WatchdogStorageProvider>,
    state: Mutex<WatchdogState>,
}

impl WatchdogManager {
    // Reconstructs one resident manager from the durable storage head.
    pub fn new(
        thresholds: WatchdogSafetyThresholds,
        samples: Arc<dyn WatchdogSampleProvider>,
        protection: Arc<dyn WatchdogProtectionProvider>,
        storage: Arc<dyn WatchdogStorageProvider>,
    ) -> Result<Self, WatchdogError> {
        let next_sequence = storage.next_sequence()?;
        if next_sequence == 0 {
            return Err(WatchdogError::InvalidContract {
                reason: "Watchdog storage returned a zero sequence",
            });
        }
        Ok(Self {
            thresholds,
            samples,
            protection,
            storage,
            state: Mutex::new(WatchdogState {
                next_sequence,
                last_unix_milliseconds: 0,
                last_monotonic_milliseconds: 0,
                warnings: BTreeMap::new(),
            }),
        })
    }

    // Runs one complete resident sample and safety lifecycle.
    pub fn tick(&self) -> Result<WatchdogTick, WatchdogError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| WatchdogError::StateUnavailable)?;
        let sample = self.samples.sample(state.next_sequence)?;
        validate_sample_order(&state, &sample)?;
        let mut observations = self.protection.observations(&sample)?;
        observations
            .sort_by(|left, right| left.target().generation().cmp(right.target().generation()));
        validate_observations(&observations)?;
        self.storage.record_sample(&sample)?;

        let mut events = Vec::new();
        let mut trips = Vec::new();
        for observation in &observations {
            let target = observation.target();
            match target.phase() {
                WatchdogProtectionPhase::Disarmed => {
                    self.protection.acknowledge_disarmed(target)?;
                    state.warnings.remove(target.generation());
                }
                WatchdogProtectionPhase::Pending => {
                    state.warnings.remove(target.generation());
                }
                WatchdogProtectionPhase::Starting | WatchdogProtectionPhase::Armed => {
                    if observation.trip_latched() {
                        continue;
                    }
                    if let Some((action, reason)) = safety_decision(observation) {
                        trips.push((observation, action, reason));
                        continue;
                    }
                    let warning = observation.safety().available_bytes
                        <= self.thresholds.warning_available_bytes();
                    let was_warning = state
                        .warnings
                        .get(target.generation())
                        .copied()
                        .unwrap_or(false);
                    if warning && !was_warning {
                        let event = WatchdogSafetyEvent::new(
                            "protection.warning",
                            "host_memory_warning",
                            1,
                            target.generation(),
                            sample.sequence(),
                            None,
                            None,
                        );
                        self.storage.record_event(&event)?;
                        events.push(event);
                    }
                    state
                        .warnings
                        .insert(target.generation().to_string(), warning);
                }
            }
        }

        if !trips.is_empty() {
            self.storage.flush()?;
        }
        for (observation, action, reason) in trips {
            let target = observation.target();
            self.protection
                .latch_trip(target, action, reason, observation.safety())?;
            let containment_complete = self
                .protection
                .contain(
                    target,
                    action,
                    self.thresholds.containment_grace_milliseconds(),
                )
                .unwrap_or(false);
            let event = WatchdogSafetyEvent::new(
                if reason == "protected_process_exited" {
                    "engine.exit"
                } else {
                    "protection.trip"
                },
                reason,
                if action == WatchdogSafetyAction::Kill {
                    3
                } else {
                    2
                },
                target.generation(),
                sample.sequence(),
                Some(action),
                Some(containment_complete),
            );
            self.storage.record_event(&event)?;
            events.push(event);
            state.warnings.remove(target.generation());
        }
        if events.iter().any(|event| event.action().is_some()) {
            self.storage.flush()?;
        }

        state.next_sequence =
            state
                .next_sequence
                .checked_add(1)
                .ok_or(WatchdogError::InvalidContract {
                    reason: "Watchdog sequence overflowed",
                })?;
        state.last_unix_milliseconds = sample.unix_milliseconds();
        state.last_monotonic_milliseconds = sample.monotonic_milliseconds();
        let protection_cycle = WatchdogProtectionCycle::completed(&sample, &observations, &events);
        Ok(WatchdogTick::new(
            sample,
            events,
            observations.len(),
            protection_cycle,
        ))
    }

    // Flushes every recorded sample and event at one resident cadence boundary.
    pub fn flush(&self) -> Result<(), WatchdogError> {
        self.storage.flush()
    }
}

// Stores the minimal process-owned state that is safe to reconstruct after restart.
struct WatchdogState {
    next_sequence: u64,
    last_unix_milliseconds: u64,
    last_monotonic_milliseconds: u64,
    warnings: BTreeMap<String, bool>,
}

// Preserves current safety policy: only an observed OOM kill or exact process exit trips.
fn safety_decision(
    observation: &WatchdogProtectionObservation,
) -> Option<(WatchdogSafetyAction, &'static str)> {
    if observation.process_state() == WatchdogProcessState::Exited {
        return Some((WatchdogSafetyAction::Stop, "protected_process_exited"));
    }
    let input = observation.safety();
    if input.cgroup_oom_kill_delta != 0 || input.cgroup_oom_group_kill_delta != 0 {
        return Some((WatchdogSafetyAction::Kill, "cgroup_oom_kill"));
    }
    None
}

// Requires strictly increasing sample identity and monotonic time.
fn validate_sample_order(
    state: &WatchdogState,
    sample: &WatchdogSample,
) -> Result<(), WatchdogError> {
    if sample.sequence() != state.next_sequence
        || sample.unix_milliseconds() < state.last_unix_milliseconds
        || sample.monotonic_milliseconds() <= state.last_monotonic_milliseconds
    {
        return Err(WatchdogError::InvalidContract {
            reason: "Watchdog sample is stale or out of order",
        });
    }
    Ok(())
}

// Requires a bounded unique sorted observation set with exact phase binding.
fn validate_observations(
    observations: &[WatchdogProtectionObservation],
) -> Result<(), WatchdogError> {
    let generations = observations
        .iter()
        .map(|observation| observation.target().generation())
        .collect::<BTreeSet<_>>();
    if observations.len() > maximum_watchdog_targets() || generations.len() != observations.len() {
        return Err(WatchdogError::InvalidContract {
            reason: "protected placement observations are duplicated or exceed their bound",
        });
    }
    Ok(())
}
