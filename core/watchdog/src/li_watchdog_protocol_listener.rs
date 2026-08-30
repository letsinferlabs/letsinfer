// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{ErrorKind, Read, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use li_core_interface::NodeId;

use crate::{
    decode_watchdog_protocol_request, encode_watchdog_protocol_frame,
    encode_watchdog_protocol_response, FilesystemWatchdogStorage, WatchdogControllerBinding,
    WatchdogControllerMutationKind, WatchdogControllerRegistry, WatchdogControllerRegistryStore,
    WatchdogError, WatchdogLiveFanout, WatchdogManager, WatchdogProtocolCapabilities,
    WatchdogProtocolRequest, WatchdogProtocolRequestKind, WatchdogProtocolResidentStatus,
    WatchdogProtocolResolution, WatchdogProtocolResponse, WatchdogProtocolResponseKind,
    WatchdogProtocolSiteStatus, WatchdogResolution, WatchdogSample, WatchdogTick,
    WATCHDOG_PROTOCOL_MAX_BATCH_SAMPLES, WATCHDOG_PROTOCOL_MAX_FRAME_BYTES,
};

pub const WATCHDOG_PROTOCOL_MAX_CONNECTIONS: usize = 16;
pub const WATCHDOG_PROTOCOL_MAX_REQUESTS_PER_CONNECTION: usize = 1_024;
pub const WATCHDOG_PROTOCOL_IDLE_TIMEOUT_MILLISECONDS: u64 = 30_000;

const WATCHDOG_PROTOCOL_MAX_HISTORY_BATCHES: usize = 675;
const WATCHDOG_PROTOCOL_REGISTRY_RETRIES: usize = 8;
const WATCHDOG_RAW_INTERVAL_MILLISECONDS: u64 = 1_000;
const WATCHDOG_MINUTE_INTERVAL_MILLISECONDS: u64 = 60_000;
const WATCHDOG_QUARTER_INTERVAL_MILLISECONDS: u64 = 900_000;
const WATCHDOG_RAW_CAPACITY: u64 = 86_400;
const WATCHDOG_MINUTE_CAPACITY: u64 = 43_200;
const WATCHDOG_QUARTER_CAPACITY: u64 = 35_040;

// Identifies a closed data-provider failure without exposing storage details.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchdogProtocolDataError {
    Unavailable,
    RangeNotRetained,
}

// Streams retained samples in bounded protocol-sized batches.
pub trait WatchdogProtocolHistoryCursor: Send {
    // Returns the next nonempty batch or the complete-history marker.
    fn next_batch(
        &mut self,
        maximum_samples: usize,
    ) -> Result<Option<Vec<WatchdogSample>>, WatchdogProtocolDataError>;

    // Returns the latest durable sequence observed when the query began.
    fn through_sequence(&self) -> u64;
}

// Supplies model-neutral protocol reads without giving the listener storage ownership.
pub trait WatchdogProtocolDataProvider: Send + Sync {
    // Returns the latest complete sample when one has been recorded.
    fn latest(&self) -> Result<Option<WatchdogSample>, WatchdogProtocolDataError>;

    // Opens one ordered bounded cursor over an exact retained interval.
    fn history(
        &self,
        resolution: WatchdogProtocolResolution,
        start_unix_milliseconds: u64,
        end_unix_milliseconds: u64,
    ) -> Result<Box<dyn WatchdogProtocolHistoryCursor>, WatchdogProtocolDataError>;

    // Returns the fixed native sampling, flushing, and GPU capability document.
    fn capabilities(&self) -> Result<WatchdogProtocolCapabilities, WatchdogProtocolDataError>;

    // Returns the current closed public site-status document.
    fn site_status(
        &self,
        binding: &WatchdogControllerBinding,
    ) -> Result<WatchdogProtocolSiteStatus, WatchdogProtocolDataError>;

    // Returns idle-safe identity and readiness for the configured resident.
    fn resident_status(&self) -> Result<WatchdogProtocolResidentStatus, WatchdogProtocolDataError>;
}

// Supplies dynamic capabilities and public identity to the native storage adapter.
pub trait WatchdogProtocolIdentityProvider: Send + Sync {
    // Returns the current fixed native timing and hardware capabilities.
    fn capabilities(&self) -> Result<WatchdogProtocolCapabilities, WatchdogProtocolDataError>;

    // Returns current validated public state without exposing private runtime data.
    fn site_status(
        &self,
        binding: &WatchdogControllerBinding,
    ) -> Result<WatchdogProtocolSiteStatus, WatchdogProtocolDataError>;

    // Returns idle-safe identity and readiness without reading placement state.
    fn resident_status(&self) -> Result<WatchdogProtocolResidentStatus, WatchdogProtocolDataError>;
}

// Adapts the existing private native rings to bounded protocol history cursors.
pub struct FilesystemWatchdogProtocolDataProvider {
    storage: Arc<FilesystemWatchdogStorage>,
    identity: Arc<dyn WatchdogProtocolIdentityProvider>,
}

impl FilesystemWatchdogProtocolDataProvider {
    // Creates one production read adapter over shared native storage and public identity.
    pub fn new(
        storage: Arc<FilesystemWatchdogStorage>,
        identity: Arc<dyn WatchdogProtocolIdentityProvider>,
    ) -> Self {
        Self { storage, identity }
    }
}

impl WatchdogProtocolDataProvider for FilesystemWatchdogProtocolDataProvider {
    // Returns the current raw storage head.
    fn latest(&self) -> Result<Option<WatchdogSample>, WatchdogProtocolDataError> {
        self.storage
            .latest_sample()
            .map_err(|_| WatchdogProtocolDataError::Unavailable)
    }

    // Opens one capacity-checked cursor over the selected native ring.
    fn history(
        &self,
        resolution: WatchdogProtocolResolution,
        start_unix_milliseconds: u64,
        end_unix_milliseconds: u64,
    ) -> Result<Box<dyn WatchdogProtocolHistoryCursor>, WatchdogProtocolDataError> {
        let (storage_resolution, interval_milliseconds, maximum_capacity) =
            history_resolution_contract(resolution);
        let layout = self
            .storage
            .history_layout(storage_resolution)
            .map_err(|_| WatchdogProtocolDataError::Unavailable)?;
        if layout.interval_milliseconds() != interval_milliseconds
            || layout.capacity() > maximum_capacity
        {
            return Err(WatchdogProtocolDataError::Unavailable);
        }
        let capacity = layout.capacity();
        let first_bucket = start_unix_milliseconds / interval_milliseconds;
        let final_bucket = end_unix_milliseconds / interval_milliseconds;
        let bucket_count = final_bucket
            .checked_sub(first_bucket)
            .and_then(|difference| difference.checked_add(1))
            .ok_or(WatchdogProtocolDataError::RangeNotRetained)?;
        if bucket_count > capacity {
            return Err(WatchdogProtocolDataError::RangeNotRetained);
        }
        let through_sequence = self
            .storage
            .latest_sample()
            .map_err(|_| WatchdogProtocolDataError::Unavailable)?
            .map(|sample| sample.sequence())
            .unwrap_or(0);
        Ok(Box::new(FilesystemWatchdogHistoryCursor {
            storage: self.storage.clone(),
            resolution: storage_resolution,
            interval_milliseconds,
            capacity,
            next_unix_milliseconds: start_unix_milliseconds,
            end_unix_milliseconds,
            through_sequence,
            complete: false,
        }))
    }

    // Delegates current timing and hardware capabilities to the identity provider.
    fn capabilities(&self) -> Result<WatchdogProtocolCapabilities, WatchdogProtocolDataError> {
        self.identity.capabilities()
    }

    // Delegates current closed public state to the identity provider.
    fn site_status(
        &self,
        binding: &WatchdogControllerBinding,
    ) -> Result<WatchdogProtocolSiteStatus, WatchdogProtocolDataError> {
        self.identity.site_status(binding)
    }

    // Delegates idle-safe identity and readiness to the resident identity provider.
    fn resident_status(&self) -> Result<WatchdogProtocolResidentStatus, WatchdogProtocolDataError> {
        self.identity.resident_status()
    }
}

// Streams one native ring without retaining the complete query in listener memory.
struct FilesystemWatchdogHistoryCursor {
    storage: Arc<FilesystemWatchdogStorage>,
    resolution: WatchdogResolution,
    interval_milliseconds: u64,
    capacity: u64,
    next_unix_milliseconds: u64,
    end_unix_milliseconds: u64,
    through_sequence: u64,
    complete: bool,
}

impl WatchdogProtocolHistoryCursor for FilesystemWatchdogHistoryCursor {
    // Reads one protocol-sized native batch and advances by its final time bucket.
    fn next_batch(
        &mut self,
        maximum_samples: usize,
    ) -> Result<Option<Vec<WatchdogSample>>, WatchdogProtocolDataError> {
        if self.complete {
            return Ok(None);
        }
        if maximum_samples == 0 || maximum_samples > WATCHDOG_PROTOCOL_MAX_BATCH_SAMPLES {
            return Err(WatchdogProtocolDataError::Unavailable);
        }
        let read_limit = maximum_samples.min(self.capacity as usize);
        let history = self
            .storage
            .history(
                self.resolution,
                self.next_unix_milliseconds,
                self.end_unix_milliseconds,
                read_limit,
            )
            .map_err(|_| WatchdogProtocolDataError::Unavailable)?;
        let samples = history.samples().to_vec();
        if samples.len() < read_limit {
            self.complete = true;
        } else if let Some(last) = samples.last() {
            let next_bucket = (last.unix_milliseconds() / self.interval_milliseconds)
                .checked_add(1)
                .ok_or(WatchdogProtocolDataError::Unavailable)?;
            self.next_unix_milliseconds = next_bucket
                .checked_mul(self.interval_milliseconds)
                .ok_or(WatchdogProtocolDataError::Unavailable)?;
            if self.next_unix_milliseconds > self.end_unix_milliseconds {
                self.complete = true;
            }
        }
        if samples.is_empty() {
            Ok(None)
        } else {
            Ok(Some(samples))
        }
    }

    // Returns the raw durable head captured when this cursor was opened.
    fn through_sequence(&self) -> u64 {
        self.through_sequence
    }
}

// Receives typed protocol responses from the one centralized dispatcher.
pub trait WatchdogProtocolResponseSink {
    // Sends one complete response without retaining an unbounded queue.
    fn send(&mut self, response: WatchdogProtocolResponse) -> Result<(), WatchdogError>;
}

// Resolves an authenticated certificate to the exact session and process binding.
pub trait WatchdogControllerSessionProvider: Send + Sync {
    // Returns a monotonic controller session only after external identity resolution.
    fn binding_for_certificate(
        &self,
        certificate_sha256: &str,
    ) -> Result<WatchdogControllerBinding, WatchdogError>;
}

// Marks a stream whose concrete adapter has already completed and verified mutual TLS.
pub trait WatchdogAuthenticatedStream: Read + Write + Send {
    // Returns the lowercase SHA-256 digest of the verified leaf certificate DER.
    fn authenticated_certificate_sha256(&self) -> Result<String, WatchdogError>;

    // Applies hard read and write deadlines before any protocol byte is consumed.
    fn configure_timeouts(
        &self,
        read_timeout: Duration,
        write_timeout: Duration,
    ) -> Result<(), WatchdogError>;
}

// Defines hard per-listener connection, request, and stream deadline bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WatchdogProtocolListenerLimits {
    maximum_connections: usize,
    maximum_requests_per_connection: usize,
    read_timeout_milliseconds: u64,
    write_timeout_milliseconds: u64,
}

impl WatchdogProtocolListenerLimits {
    // Creates one listener limit set inside the unchanged C daemon hard bounds.
    pub fn new(
        maximum_connections: usize,
        maximum_requests_per_connection: usize,
        read_timeout_milliseconds: u64,
        write_timeout_milliseconds: u64,
    ) -> Result<Self, WatchdogError> {
        if maximum_connections == 0
            || maximum_connections > WATCHDOG_PROTOCOL_MAX_CONNECTIONS
            || maximum_requests_per_connection == 0
            || maximum_requests_per_connection > WATCHDOG_PROTOCOL_MAX_REQUESTS_PER_CONNECTION
            || !(1..=WATCHDOG_PROTOCOL_IDLE_TIMEOUT_MILLISECONDS)
                .contains(&read_timeout_milliseconds)
            || !(1..=WATCHDOG_PROTOCOL_IDLE_TIMEOUT_MILLISECONDS)
                .contains(&write_timeout_milliseconds)
        {
            return Err(listener_error("protocol listener limits are invalid"));
        }
        Ok(Self {
            maximum_connections,
            maximum_requests_per_connection,
            read_timeout_milliseconds,
            write_timeout_milliseconds,
        })
    }

    // Returns the existing production C listener limits.
    pub fn production() -> Self {
        Self::new(
            WATCHDOG_PROTOCOL_MAX_CONNECTIONS,
            WATCHDOG_PROTOCOL_MAX_REQUESTS_PER_CONNECTION,
            WATCHDOG_PROTOCOL_IDLE_TIMEOUT_MILLISECONDS,
            WATCHDOG_PROTOCOL_IDLE_TIMEOUT_MILLISECONDS,
        )
        .expect("fixed Watchdog protocol listener limits")
    }
}

impl Default for WatchdogProtocolListenerLimits {
    // Returns the existing production C listener limits.
    fn default() -> Self {
        Self::production()
    }
}

// Reports whether one request completed normally or established a live subscription.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WatchdogProtocolDispatchResult {
    subscription_request_id: Option<u64>,
    succeeded: bool,
}

impl WatchdogProtocolDispatchResult {
    // Creates one ordinary non-streaming dispatch result.
    const fn completed() -> Self {
        Self {
            subscription_request_id: None,
            succeeded: true,
        }
    }

    // Creates one result after a redacted application failure was sent.
    const fn failed() -> Self {
        Self {
            subscription_request_id: None,
            succeeded: false,
        }
    }

    // Creates one accepted live-subscription dispatch result.
    const fn subscribed(request_id: u64) -> Self {
        Self {
            subscription_request_id: Some(request_id),
            succeeded: true,
        }
    }

    // Returns the request identity reserved for future live samples.
    pub const fn subscription_request_id(self) -> Option<u64> {
        self.subscription_request_id
    }

    // Returns whether the requested operation completed without an application error.
    pub const fn succeeded(self) -> bool {
        self.succeeded
    }
}

// Owns all request-family routing and redacted public failure language.
pub struct WatchdogProtocolDispatcher {
    data: Arc<dyn WatchdogProtocolDataProvider>,
}

impl WatchdogProtocolDispatcher {
    // Creates one centralized dispatcher over an injected bounded data provider.
    pub fn new(data: Arc<dyn WatchdogProtocolDataProvider>) -> Self {
        Self { data }
    }

    // Dispatches exactly one typed request through the closed protocol-v3 surface.
    pub fn dispatch(
        &self,
        binding: &WatchdogControllerBinding,
        request: &WatchdogProtocolRequest,
        sink: &mut dyn WatchdogProtocolResponseSink,
    ) -> Result<WatchdogProtocolDispatchResult, WatchdogError> {
        match request.kind() {
            WatchdogProtocolRequestKind::GetLatest => {
                self.dispatch_latest(request.request_id(), sink)
            }
            WatchdogProtocolRequestKind::Subscribe { history_seconds } => {
                self.dispatch_subscribe(request.request_id(), *history_seconds, sink)
            }
            WatchdogProtocolRequestKind::QueryRange {
                start_unix_milliseconds,
                end_unix_milliseconds,
                resolution,
            } => self.dispatch_history(
                request.request_id(),
                *start_unix_milliseconds,
                *end_unix_milliseconds,
                *resolution,
                None,
                sink,
            ),
            WatchdogProtocolRequestKind::GetCapabilities => {
                let succeeded = match self.data.capabilities() {
                    Ok(capabilities) => send_response(
                        sink,
                        request.request_id(),
                        WatchdogProtocolResponseKind::Capabilities(capabilities),
                    )
                    .map(|_| true)?,
                    Err(error) => {
                        send_data_error(sink, request.request_id(), error).map(|_| false)?
                    }
                };
                Ok(if succeeded {
                    WatchdogProtocolDispatchResult::completed()
                } else {
                    WatchdogProtocolDispatchResult::failed()
                })
            }
            WatchdogProtocolRequestKind::Ping { nonce } => {
                send_response(
                    sink,
                    request.request_id(),
                    WatchdogProtocolResponseKind::Pong { nonce: *nonce },
                )?;
                Ok(WatchdogProtocolDispatchResult::completed())
            }
            WatchdogProtocolRequestKind::GetSiteStatus => {
                let succeeded = match self.data.site_status(binding) {
                    Ok(status) => send_response(
                        sink,
                        request.request_id(),
                        WatchdogProtocolResponseKind::SiteStatus(status),
                    )
                    .map(|_| true)?,
                    Err(error) => {
                        send_data_error(sink, request.request_id(), error).map(|_| false)?
                    }
                };
                Ok(if succeeded {
                    WatchdogProtocolDispatchResult::completed()
                } else {
                    WatchdogProtocolDispatchResult::failed()
                })
            }
            WatchdogProtocolRequestKind::GetResidentStatus => {
                self.dispatch_resident_status(request.request_id(), sink)
            }
        }
    }

    // Dispatches the idle-safe resident identity without requiring target-bound state.
    fn dispatch_resident_status(
        &self,
        request_id: u64,
        sink: &mut dyn WatchdogProtocolResponseSink,
    ) -> Result<WatchdogProtocolDispatchResult, WatchdogError> {
        let succeeded = match self.data.resident_status() {
            Ok(status) => send_response(
                sink,
                request_id,
                WatchdogProtocolResponseKind::ResidentStatus(status),
            )
            .map(|_| true)?,
            Err(error) => send_data_error(sink, request_id, error).map(|_| false)?,
        };
        Ok(if succeeded {
            WatchdogProtocolDispatchResult::completed()
        } else {
            WatchdogProtocolDispatchResult::failed()
        })
    }

    // Dispatches one latest-sample request with the existing 404 contract.
    fn dispatch_latest(
        &self,
        request_id: u64,
        sink: &mut dyn WatchdogProtocolResponseSink,
    ) -> Result<WatchdogProtocolDispatchResult, WatchdogError> {
        let succeeded = match self.data.latest() {
            Ok(Some(sample)) => {
                send_response(
                    sink,
                    request_id,
                    WatchdogProtocolResponseKind::Latest(sample),
                )?;
                true
            }
            Ok(None) => {
                send_public_error(sink, request_id, 404, "no sample available")?;
                false
            }
            Err(error) => {
                send_data_error(sink, request_id, error)?;
                false
            }
        };
        Ok(if succeeded {
            WatchdogProtocolDispatchResult::completed()
        } else {
            WatchdogProtocolDispatchResult::failed()
        })
    }

    // Dispatches initial latest and retained history before reserving a live stream.
    fn dispatch_subscribe(
        &self,
        request_id: u64,
        history_seconds: u32,
        sink: &mut dyn WatchdogProtocolResponseSink,
    ) -> Result<WatchdogProtocolDispatchResult, WatchdogError> {
        let latest = match self.data.latest() {
            Ok(Some(sample)) => sample,
            Ok(None) => {
                send_public_error(sink, request_id, 404, "no sample available")?;
                return Ok(WatchdogProtocolDispatchResult::failed());
            }
            Err(error) => {
                send_data_error(sink, request_id, error)?;
                return Ok(WatchdogProtocolDispatchResult::failed());
            }
        };
        send_response(
            sink,
            request_id,
            WatchdogProtocolResponseKind::Latest(latest.clone()),
        )?;
        if history_seconds != 0 {
            let capabilities = match self.data.capabilities() {
                Ok(capabilities) => capabilities,
                Err(error) => {
                    send_data_error(sink, request_id, error)?;
                    return Ok(WatchdogProtocolDispatchResult::failed());
                }
            };
            let end_unix_milliseconds = latest
                .unix_milliseconds()
                .saturating_sub(u64::from(capabilities.sample_interval_milliseconds()));
            let start_unix_milliseconds =
                end_unix_milliseconds.saturating_sub(u64::from(history_seconds) * 1_000);
            let completed = self.dispatch_history(
                request_id,
                start_unix_milliseconds,
                end_unix_milliseconds,
                WatchdogProtocolResolution::RawOneSecond,
                Some(latest.sequence()),
                sink,
            )?;
            if completed.subscription_request_id().is_some() {
                return Err(listener_error("nested subscription state is invalid"));
            }
            if !completed.succeeded() {
                return Ok(WatchdogProtocolDispatchResult::failed());
            }
        } else {
            send_response(
                sink,
                request_id,
                WatchdogProtocolResponseKind::HistoryComplete {
                    through_sequence: latest.sequence(),
                },
            )?;
        }
        Ok(WatchdogProtocolDispatchResult::subscribed(request_id))
    }

    // Streams one retained query without allocating its complete result set.
    fn dispatch_history(
        &self,
        request_id: u64,
        start_unix_milliseconds: u64,
        end_unix_milliseconds: u64,
        resolution: WatchdogProtocolResolution,
        through_sequence: Option<u64>,
        sink: &mut dyn WatchdogProtocolResponseSink,
    ) -> Result<WatchdogProtocolDispatchResult, WatchdogError> {
        let mut cursor =
            match self
                .data
                .history(resolution, start_unix_milliseconds, end_unix_milliseconds)
            {
                Ok(cursor) => cursor,
                Err(error) => {
                    send_data_error(sink, request_id, error)?;
                    return Ok(WatchdogProtocolDispatchResult::failed());
                }
            };
        let through_sequence = through_sequence.unwrap_or_else(|| cursor.through_sequence());
        let mut last_sequence = None;
        let mut last_unix_milliseconds = None;
        for batch_index in 0..=WATCHDOG_PROTOCOL_MAX_HISTORY_BATCHES {
            let samples = match cursor.next_batch(WATCHDOG_PROTOCOL_MAX_BATCH_SAMPLES) {
                Ok(None) => {
                    send_response(
                        sink,
                        request_id,
                        WatchdogProtocolResponseKind::HistoryComplete { through_sequence },
                    )?;
                    return Ok(WatchdogProtocolDispatchResult::completed());
                }
                Ok(Some(samples)) => samples,
                Err(error) => {
                    send_data_error(sink, request_id, error)?;
                    return Ok(WatchdogProtocolDispatchResult::failed());
                }
            };
            if batch_index == WATCHDOG_PROTOCOL_MAX_HISTORY_BATCHES
                || !valid_history_batch(
                    &samples,
                    start_unix_milliseconds,
                    end_unix_milliseconds,
                    &mut last_sequence,
                    &mut last_unix_milliseconds,
                )
            {
                send_data_error(sink, request_id, WatchdogProtocolDataError::Unavailable)?;
                return Ok(WatchdogProtocolDispatchResult::failed());
            }
            send_response(
                sink,
                request_id,
                WatchdogProtocolResponseKind::HistoryBatch(samples),
            )?;
        }
        Err(listener_error("history dispatch exceeded its bound"))
    }
}

// Owns the accepted-stream protocol boundary and every live controller lease.
pub struct WatchdogProtocolListener {
    dispatcher: Arc<WatchdogProtocolDispatcher>,
    registry: Arc<WatchdogControllerRegistryStore>,
    sessions: Arc<dyn WatchdogControllerSessionProvider>,
    resident_status_controller_id: NodeId,
    limits: WatchdogProtocolListenerLimits,
    active_connections: Arc<AtomicUsize>,
}

impl WatchdogProtocolListener {
    // Creates one bounded listener after all authenticated dependencies are supplied.
    pub fn new(
        dispatcher: Arc<WatchdogProtocolDispatcher>,
        registry: Arc<WatchdogControllerRegistry>,
        sessions: Arc<dyn WatchdogControllerSessionProvider>,
        resident_status_controller_id: NodeId,
        limits: WatchdogProtocolListenerLimits,
    ) -> Self {
        Self {
            dispatcher,
            registry: Arc::new(WatchdogControllerRegistryStore::new(registry)),
            sessions,
            resident_status_controller_id,
            limits,
            active_connections: Arc::new(AtomicUsize::new(0)),
        }
    }

    // Creates one listener around a shared atomic last-good registry store.
    pub fn new_with_registry_store(
        dispatcher: Arc<WatchdogProtocolDispatcher>,
        registry: Arc<WatchdogControllerRegistryStore>,
        sessions: Arc<dyn WatchdogControllerSessionProvider>,
        resident_status_controller_id: NodeId,
        limits: WatchdogProtocolListenerLimits,
    ) -> Self {
        Self {
            dispatcher,
            registry,
            sessions,
            resident_status_controller_id,
            limits,
            active_connections: Arc::new(AtomicUsize::new(0)),
        }
    }

    // Returns the shared registry store used for exact resident reload.
    pub fn controller_registry_store(&self) -> Arc<WatchdogControllerRegistryStore> {
        self.registry.clone()
    }

    // Returns whether controller generations are reconstructed before native acceptance.
    pub fn has_persistent_controller_registry(&self) -> bool {
        self.registry
            .current()
            .is_ok_and(|(_, registry)| registry.is_persistent())
    }

    // Serves one stream only after its concrete adapter has completed mutual TLS.
    pub fn serve_authenticated_stream(
        &self,
        stream: &mut dyn WatchdogAuthenticatedStream,
    ) -> Result<WatchdogProtocolConnectionOutcome, WatchdogError> {
        let slot = WatchdogConnectionSlot::acquire(
            self.active_connections.clone(),
            self.limits.maximum_connections,
        )?;
        stream.configure_timeouts(
            Duration::from_millis(self.limits.read_timeout_milliseconds),
            Duration::from_millis(self.limits.write_timeout_milliseconds),
        )?;
        let certificate_sha256 = stream.authenticated_certificate_sha256()?;
        let (registry_generation, registry) = self.registry.current()?;
        if registry.authorizes_controller(
            self.resident_status_controller_id.as_str(),
            &certificate_sha256,
        ) {
            return self.serve_resident_status_stream(stream, slot, registry_generation, registry);
        }
        let binding = self.sessions.binding_for_certificate(&certificate_sha256)?;
        if binding.certificate_sha256() != certificate_sha256 {
            return Err(listener_error(
                "authenticated controller identity does not match",
            ));
        }
        let mutation = apply_controller_binding(&registry, &binding)?;
        if mutation == WatchdogControllerMutationKind::Replayed {
            return Err(listener_error("controller session replay was rejected"));
        }
        let lease = WatchdogControllerLease::new(
            self.registry.clone(),
            registry_generation,
            registry,
            binding,
        );
        let mut sink = WatchdogStreamResponseSink { stream };
        for _ in 0..self.limits.maximum_requests_per_connection {
            if !lease.is_active()? {
                return Err(listener_error("controller session is no longer active"));
            }
            let payload = match read_protocol_frame(sink.stream)? {
                Some(payload) => payload,
                None => return Ok(WatchdogProtocolConnectionOutcome::Completed),
            };
            let request = match decode_watchdog_protocol_request(&payload) {
                Ok(request) => request,
                Err(_) => {
                    send_public_error(&mut sink, 0, 400, "invalid protobuf request")?;
                    return Ok(WatchdogProtocolConnectionOutcome::Completed);
                }
            };
            let result = self
                .dispatcher
                .dispatch(lease.binding(), &request, &mut sink)?;
            if let Some(request_id) = result.subscription_request_id() {
                return Ok(WatchdogProtocolConnectionOutcome::Subscribed(
                    WatchdogProtocolSubscription {
                        request_id,
                        certificate_sha256,
                        lease: Some(lease),
                        slot: Some(slot),
                    },
                ));
            }
        }
        Ok(WatchdogProtocolConnectionOutcome::Completed)
    }

    // Serves exactly one idle-safe readiness read without creating a runtime protection lease.
    fn serve_resident_status_stream(
        &self,
        stream: &mut dyn WatchdogAuthenticatedStream,
        _slot: WatchdogConnectionSlot,
        registry_generation: u64,
        registry: Arc<WatchdogControllerRegistry>,
    ) -> Result<WatchdogProtocolConnectionOutcome, WatchdogError> {
        let mut sink = WatchdogStreamResponseSink { stream };
        let payload = match read_protocol_frame(sink.stream)? {
            Some(payload) => payload,
            None => return Ok(WatchdogProtocolConnectionOutcome::Completed),
        };
        let request = match decode_watchdog_protocol_request(&payload) {
            Ok(request) => request,
            Err(_) => {
                send_public_error(&mut sink, 0, 400, "invalid protobuf request")?;
                return Ok(WatchdogProtocolConnectionOutcome::Completed);
            }
        };
        if !matches!(
            request.kind(),
            WatchdogProtocolRequestKind::GetResidentStatus
        ) {
            send_public_error(
                &mut sink,
                request.request_id(),
                403,
                "controller is not authorized for request",
            )?;
            return Ok(WatchdogProtocolConnectionOutcome::Completed);
        }
        if !self.registry.is_current(registry_generation, &registry)? {
            return Err(listener_error("controller trust is no longer active"));
        }
        self.dispatcher
            .dispatch_resident_status(request.request_id(), &mut sink)?;
        Ok(WatchdogProtocolConnectionOutcome::Completed)
    }
}

// Composes resident sampling and the authenticated protocol listener without merging roles.
pub struct WatchdogProtocolService {
    manager: Arc<WatchdogManager>,
    listener: Arc<WatchdogProtocolListener>,
    fanout: Option<Arc<WatchdogLiveFanout>>,
}

impl WatchdogProtocolService {
    // Creates one resident service from the existing manager and bounded listener.
    pub fn new(manager: Arc<WatchdogManager>, listener: Arc<WatchdogProtocolListener>) -> Self {
        Self {
            manager,
            listener,
            fanout: None,
        }
    }

    // Creates one resident service that publishes only successfully committed manager ticks.
    pub fn new_with_fanout(
        manager: Arc<WatchdogManager>,
        listener: Arc<WatchdogProtocolListener>,
        fanout: Arc<WatchdogLiveFanout>,
    ) -> Self {
        Self {
            manager,
            listener,
            fanout: Some(fanout),
        }
    }

    // Runs one complete existing Watchdog sampling and protection tick.
    pub fn tick(&self) -> Result<WatchdogTick, WatchdogError> {
        let tick = self.manager.tick()?;
        if let Some(fanout) = &self.fanout {
            fanout.publish(tick.sample())?;
        }
        Ok(tick)
    }

    // Flushes every durable Watchdog record at one resident lifecycle boundary.
    pub fn flush(&self) -> Result<(), WatchdogError> {
        self.manager.flush()
    }

    // Dispatches one already-authenticated accepted stream.
    pub fn serve_authenticated_stream(
        &self,
        stream: &mut dyn WatchdogAuthenticatedStream,
    ) -> Result<WatchdogProtocolConnectionOutcome, WatchdogError> {
        self.listener.serve_authenticated_stream(stream)
    }
}

// Reports the terminal state of one accepted authenticated stream.
pub enum WatchdogProtocolConnectionOutcome {
    Completed,
    Subscribed(WatchdogProtocolSubscription),
}

// Retains the controller and connection slots while a live stream remains active.
pub struct WatchdogProtocolSubscription {
    request_id: u64,
    certificate_sha256: String,
    lease: Option<WatchdogControllerLease>,
    slot: Option<WatchdogConnectionSlot>,
}

impl WatchdogProtocolSubscription {
    // Returns the request identity used by every future live response.
    pub const fn request_id(&self) -> u64 {
        self.request_id
    }

    // Returns whether this exact controller generation still owns its registry lease.
    pub fn is_active(&self) -> Result<bool, WatchdogError> {
        self.lease
            .as_ref()
            .ok_or_else(|| listener_error("controller subscription is inactive"))?
            .is_active()
    }

    // Returns whether this stream digest and controller generation remain exactly authorized.
    pub fn is_authorized_for(
        &self,
        stream: &dyn WatchdogAuthenticatedStream,
    ) -> Result<bool, WatchdogError> {
        Ok(
            stream.authenticated_certificate_sha256()? == self.certificate_sha256
                && self.is_active()?,
        )
    }

    // Sends one live sample only while the exact authenticated session remains active.
    pub fn send_live_sample(
        &self,
        stream: &mut dyn WatchdogAuthenticatedStream,
        sample: WatchdogSample,
    ) -> Result<(), WatchdogError> {
        self.validate_stream(stream)?;
        write_stream_response(
            stream,
            WatchdogProtocolResponse::new(
                self.request_id,
                WatchdogProtocolResponseKind::Live(sample),
            )?,
        )
    }

    // Sends one explicit live gap without inferring or hiding lost sequences.
    pub fn send_gap(
        &self,
        stream: &mut dyn WatchdogAuthenticatedStream,
        first_missing_sequence: u64,
        latest_sequence: u64,
    ) -> Result<(), WatchdogError> {
        self.validate_stream(stream)?;
        write_stream_response(
            stream,
            WatchdogProtocolResponse::new(
                self.request_id,
                WatchdogProtocolResponseKind::Gap {
                    first_missing_sequence,
                    latest_sequence,
                },
            )?,
        )
    }

    // Revalidates both the TLS leaf digest and current registry generation.
    fn validate_stream(
        &self,
        stream: &dyn WatchdogAuthenticatedStream,
    ) -> Result<(), WatchdogError> {
        if !self.is_authorized_for(stream)? {
            return Err(listener_error(
                "controller subscription is no longer authorized",
            ));
        }
        Ok(())
    }
}

impl Drop for WatchdogProtocolSubscription {
    // Releases the registry lease before making the connection slot reusable.
    fn drop(&mut self) {
        self.lease.take();
        self.slot.take();
    }
}

// Holds one active registry generation and retires it on every terminal path.
struct WatchdogControllerLease {
    store: Arc<WatchdogControllerRegistryStore>,
    registry_generation: u64,
    registry: Arc<WatchdogControllerRegistry>,
    binding: WatchdogControllerBinding,
}

impl WatchdogControllerLease {
    // Creates one lease after a successful non-replayed registry mutation.
    fn new(
        store: Arc<WatchdogControllerRegistryStore>,
        registry_generation: u64,
        registry: Arc<WatchdogControllerRegistry>,
        binding: WatchdogControllerBinding,
    ) -> Self {
        Self {
            store,
            registry_generation,
            registry,
            binding,
        }
    }

    // Returns whether this exact controller and protected process remain active.
    fn is_active(&self) -> Result<bool, WatchdogError> {
        Ok(self
            .store
            .is_current(self.registry_generation, &self.registry)?
            && self.registry.is_active(&self.binding)?)
    }

    // Returns the exact authenticated controller and protected-process binding.
    fn binding(&self) -> &WatchdogControllerBinding {
        &self.binding
    }
}

impl Drop for WatchdogControllerLease {
    // Retires this generation under bounded optimistic retries unless it was superseded.
    fn drop(&mut self) {
        if !self
            .store
            .is_current(self.registry_generation, &self.registry)
            .unwrap_or(false)
        {
            return;
        }
        for _ in 0..WATCHDOG_PROTOCOL_REGISTRY_RETRIES {
            if !self.registry.is_active(&self.binding).unwrap_or(false) {
                return;
            }
            let revision = match self.registry.revision() {
                Ok(revision) => revision,
                Err(_) => return,
            };
            if self
                .registry
                .retire(
                    self.binding.controller_id(),
                    self.binding.session_generation(),
                    revision,
                )
                .is_ok()
            {
                return;
            }
        }
    }
}

// Holds one hard listener slot and releases it on every terminal path.
struct WatchdogConnectionSlot {
    active_connections: Arc<AtomicUsize>,
}

impl WatchdogConnectionSlot {
    // Atomically acquires one connection slot without exceeding the listener bound.
    fn acquire(
        active_connections: Arc<AtomicUsize>,
        maximum_connections: usize,
    ) -> Result<Self, WatchdogError> {
        let acquired =
            active_connections.fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < maximum_connections).then_some(current + 1)
            });
        if acquired.is_err() {
            return Err(listener_error(
                "protocol listener connection bound was reached",
            ));
        }
        Ok(Self { active_connections })
    }
}

impl Drop for WatchdogConnectionSlot {
    // Releases exactly one previously acquired listener connection slot.
    fn drop(&mut self) {
        self.active_connections.fetch_sub(1, Ordering::AcqRel);
    }
}

// Writes typed responses directly to one bounded accepted stream.
struct WatchdogStreamResponseSink<'a> {
    stream: &'a mut dyn WatchdogAuthenticatedStream,
}

impl WatchdogProtocolResponseSink for WatchdogStreamResponseSink<'_> {
    // Encodes and flushes one response without retaining a connection output queue.
    fn send(&mut self, response: WatchdogProtocolResponse) -> Result<(), WatchdogError> {
        write_stream_response(self.stream, response)
    }
}

// Applies one controller generation under a bounded optimistic concurrency loop.
fn apply_controller_binding(
    registry: &WatchdogControllerRegistry,
    binding: &WatchdogControllerBinding,
) -> Result<WatchdogControllerMutationKind, WatchdogError> {
    let mut last_error = None;
    for _ in 0..WATCHDOG_PROTOCOL_REGISTRY_RETRIES {
        let revision = registry.revision()?;
        match registry.apply(binding.clone(), revision) {
            Ok(mutation) => return Ok(mutation.kind()),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| listener_error("controller registry is unavailable")))
}

// Maps each protocol resolution to the unchanged native ring contract.
const fn history_resolution_contract(
    resolution: WatchdogProtocolResolution,
) -> (WatchdogResolution, u64, u64) {
    match resolution {
        WatchdogProtocolResolution::RawOneSecond => (
            WatchdogResolution::Raw,
            WATCHDOG_RAW_INTERVAL_MILLISECONDS,
            WATCHDOG_RAW_CAPACITY,
        ),
        WatchdogProtocolResolution::OneMinute => (
            WatchdogResolution::Minute,
            WATCHDOG_MINUTE_INTERVAL_MILLISECONDS,
            WATCHDOG_MINUTE_CAPACITY,
        ),
        WatchdogProtocolResolution::FifteenMinutes => (
            WatchdogResolution::QuarterHour,
            WATCHDOG_QUARTER_INTERVAL_MILLISECONDS,
            WATCHDOG_QUARTER_CAPACITY,
        ),
    }
}

// Reads one exact length-prefixed frame with no allocation before validating its bound.
fn read_protocol_frame(
    stream: &mut dyn WatchdogAuthenticatedStream,
) -> Result<Option<Vec<u8>>, WatchdogError> {
    let mut header = [0_u8; 4];
    if !read_exact_bounded(stream, &mut header, true)? {
        return Ok(None);
    }
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > WATCHDOG_PROTOCOL_MAX_FRAME_BYTES {
        return Err(listener_error("protocol frame length is invalid"));
    }
    let mut payload = vec![0_u8; length];
    read_exact_bounded(stream, &mut payload, false)?;
    Ok(Some(payload))
}

// Reads an exact byte count while distinguishing clean initial EOF from truncation.
fn read_exact_bounded(
    stream: &mut dyn WatchdogAuthenticatedStream,
    output: &mut [u8],
    allow_initial_eof: bool,
) -> Result<bool, WatchdogError> {
    let mut offset = 0;
    while offset < output.len() {
        match stream.read(&mut output[offset..]) {
            Ok(0) if allow_initial_eof && offset == 0 => return Ok(false),
            Ok(0) => return Err(listener_error("authenticated protocol frame is truncated")),
            Ok(count) => offset += count,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) if matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => {
                return Err(listener_error("authenticated protocol stream timed out"))
            }
            Err(_) => return Err(listener_error("authenticated protocol stream read failed")),
        }
    }
    Ok(true)
}

// Encodes, frames, writes, and flushes one complete typed response.
fn write_stream_response(
    stream: &mut dyn WatchdogAuthenticatedStream,
    response: WatchdogProtocolResponse,
) -> Result<(), WatchdogError> {
    let payload = encode_watchdog_protocol_response(&response)?;
    let frame = encode_watchdog_protocol_frame(&payload)?;
    stream
        .write_all(&frame)
        .and_then(|_| stream.flush())
        .map_err(|error| {
            if matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) {
                listener_error("authenticated protocol stream timed out")
            } else {
                listener_error("authenticated protocol stream write failed")
            }
        })
}

// Validates one provider batch against protocol, range, and strict ordering bounds.
fn valid_history_batch(
    samples: &[WatchdogSample],
    start_unix_milliseconds: u64,
    end_unix_milliseconds: u64,
    last_sequence: &mut Option<u64>,
    last_unix_milliseconds: &mut Option<u64>,
) -> bool {
    if samples.is_empty() || samples.len() > WATCHDOG_PROTOCOL_MAX_BATCH_SAMPLES {
        return false;
    }
    for sample in samples {
        if sample.unix_milliseconds() < start_unix_milliseconds
            || sample.unix_milliseconds() > end_unix_milliseconds
            || last_sequence.is_some_and(|sequence| sample.sequence() <= sequence)
            || last_unix_milliseconds
                .is_some_and(|milliseconds| sample.unix_milliseconds() < milliseconds)
        {
            return false;
        }
        *last_sequence = Some(sample.sequence());
        *last_unix_milliseconds = Some(sample.unix_milliseconds());
    }
    true
}

// Sends one typed response body under its caller request identity.
fn send_response(
    sink: &mut dyn WatchdogProtocolResponseSink,
    request_id: u64,
    kind: WatchdogProtocolResponseKind,
) -> Result<(), WatchdogError> {
    sink.send(WatchdogProtocolResponse::new(request_id, kind)?)
}

// Maps one closed provider failure to stable public status and language.
fn send_data_error(
    sink: &mut dyn WatchdogProtocolResponseSink,
    request_id: u64,
    error: WatchdogProtocolDataError,
) -> Result<(), WatchdogError> {
    match error {
        WatchdogProtocolDataError::RangeNotRetained => {
            send_public_error(sink, request_id, 413, "range exceeds retained history")
        }
        WatchdogProtocolDataError::Unavailable => send_public_error(
            sink,
            request_id,
            503,
            "Watchdog telemetry is temporarily unavailable",
        ),
    }
}

// Sends one closed redacted protocol error without provider details.
fn send_public_error(
    sink: &mut dyn WatchdogProtocolResponseSink,
    request_id: u64,
    code: u32,
    message: &'static str,
) -> Result<(), WatchdogError> {
    send_response(
        sink,
        request_id,
        WatchdogProtocolResponseKind::Error {
            code,
            message: message.to_string(),
        },
    )
}

// Creates one stable redacted accepted-stream listener failure.
const fn listener_error(reason: &'static str) -> WatchdogError {
    WatchdogError::provider("protocol listener", reason)
}
