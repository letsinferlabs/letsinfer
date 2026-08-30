// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::VecDeque;
use std::fs;
use std::io::{Cursor, Error, ErrorKind, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use li_core_interface::{InstallationId, NodeId, Sha256Digest};
use li_watchdog_manager::{
    decode_watchdog_protocol_frame, decode_watchdog_protocol_response,
    encode_watchdog_protocol_frame, encode_watchdog_protocol_request,
    FilesystemWatchdogProtocolDataProvider, FilesystemWatchdogStorage, WatchdogAuthenticatedStream,
    WatchdogControllerAllowlist, WatchdogControllerBinding, WatchdogControllerRegistry,
    WatchdogControllerSessionProvider, WatchdogError, WatchdogLiveFanout, WatchdogLiveFanoutLimits,
    WatchdogLivePublishKind, WatchdogManager, WatchdogProtectedEngine,
    WatchdogProtectionObservation, WatchdogProtectionProvider, WatchdogProtocolCapabilities,
    WatchdogProtocolConnectionOutcome, WatchdogProtocolDataError, WatchdogProtocolDataProvider,
    WatchdogProtocolDispatcher, WatchdogProtocolHistoryCursor, WatchdogProtocolIdentityProvider,
    WatchdogProtocolListener, WatchdogProtocolListenerLimits, WatchdogProtocolRequest,
    WatchdogProtocolRequestKind, WatchdogProtocolResidentStatus, WatchdogProtocolResolution,
    WatchdogProtocolResponse, WatchdogProtocolResponseKind, WatchdogProtocolResponseSink,
    WatchdogProtocolService, WatchdogProtocolSiteStatus, WatchdogSafetyAction, WatchdogSafetyEvent,
    WatchdogSafetyInput, WatchdogSafetyThresholds, WatchdogSample, WatchdogSampleProvider,
    WatchdogStorageLayout, WatchdogStorageProvider,
};
use tempfile::tempdir;

// Dispatches every protocol-v3 request family through one typed central path.
#[test]
fn protocol_dispatcher_covers_every_request_family() {
    let data = Arc::new(MockDataProvider::ordinary());
    let dispatcher = WatchdogProtocolDispatcher::new(data);
    let controller = binding('a', '1', 1, 'a', 101);

    let cases = [
        WatchdogProtocolRequest::new(1, WatchdogProtocolRequestKind::GetLatest).unwrap(),
        WatchdogProtocolRequest::new(
            2,
            WatchdogProtocolRequestKind::QueryRange {
                start_unix_milliseconds: 1_000,
                end_unix_milliseconds: 3_000,
                resolution: WatchdogProtocolResolution::RawOneSecond,
            },
        )
        .unwrap(),
        WatchdogProtocolRequest::new(3, WatchdogProtocolRequestKind::GetCapabilities).unwrap(),
        WatchdogProtocolRequest::new(4, WatchdogProtocolRequestKind::Ping { nonce: 99 }).unwrap(),
        WatchdogProtocolRequest::new(5, WatchdogProtocolRequestKind::GetSiteStatus).unwrap(),
        WatchdogProtocolRequest::new(6, WatchdogProtocolRequestKind::GetResidentStatus).unwrap(),
    ];
    let mut sink = RecordingSink::default();
    for request in &cases {
        let result = dispatcher
            .dispatch(&controller, request, &mut sink)
            .unwrap();
        assert!(result.succeeded());
        assert_eq!(result.subscription_request_id(), None);
    }
    assert!(matches!(
        sink.responses[0].kind(),
        WatchdogProtocolResponseKind::Latest(sample) if sample.sequence() == 4
    ));
    assert!(matches!(
        sink.responses[1].kind(),
        WatchdogProtocolResponseKind::HistoryBatch(samples) if samples.len() == 2
    ));
    assert!(matches!(
        sink.responses[2].kind(),
        WatchdogProtocolResponseKind::HistoryBatch(samples) if samples.len() == 1
    ));
    assert!(matches!(
        sink.responses[3].kind(),
        WatchdogProtocolResponseKind::HistoryComplete {
            through_sequence: 4
        }
    ));
    assert!(matches!(
        sink.responses[4].kind(),
        WatchdogProtocolResponseKind::Capabilities(_)
    ));
    assert!(matches!(
        sink.responses[5].kind(),
        WatchdogProtocolResponseKind::Pong { nonce: 99 }
    ));
    assert!(matches!(
        sink.responses[6].kind(),
        WatchdogProtocolResponseKind::SiteStatus(_)
    ));
    assert!(matches!(
        sink.responses[7].kind(),
        WatchdogProtocolResponseKind::ResidentStatus(_)
    ));

    let subscribe = WatchdogProtocolRequest::new(
        6,
        WatchdogProtocolRequestKind::Subscribe { history_seconds: 2 },
    )
    .unwrap();
    let mut sink = RecordingSink::default();
    let result = dispatcher
        .dispatch(&controller, &subscribe, &mut sink)
        .unwrap();
    assert!(result.succeeded());
    assert_eq!(result.subscription_request_id(), Some(6));
    assert!(matches!(
        sink.responses.first().unwrap().kind(),
        WatchdogProtocolResponseKind::Latest(sample) if sample.sequence() == 4
    ));
    assert!(matches!(
        sink.responses.last().unwrap().kind(),
        WatchdogProtocolResponseKind::HistoryComplete {
            through_sequence: 4
        }
    ));
}

// Maps absent, unavailable, unretained, malformed-provider, and sink failures safely.
#[test]
fn protocol_dispatcher_redacts_and_bounds_provider_failures() {
    let controller = binding('a', '1', 1, 'a', 101);
    let request = WatchdogProtocolRequest::new(8, WatchdogProtocolRequestKind::GetLatest).unwrap();
    let unavailable = Arc::new(MockDataProvider::with_latest_error(
        WatchdogProtocolDataError::Unavailable,
    ));
    let mut sink = RecordingSink::default();
    let result = WatchdogProtocolDispatcher::new(unavailable)
        .dispatch(&controller, &request, &mut sink)
        .unwrap();
    assert!(!result.succeeded());
    assert_error(
        &sink.responses[0],
        503,
        "Watchdog telemetry is temporarily unavailable",
    );

    let absent = Arc::new(MockDataProvider::without_latest());
    let mut sink = RecordingSink::default();
    WatchdogProtocolDispatcher::new(absent)
        .dispatch(&controller, &request, &mut sink)
        .unwrap();
    assert_error(&sink.responses[0], 404, "no sample available");

    let range = WatchdogProtocolRequest::new(
        9,
        WatchdogProtocolRequestKind::QueryRange {
            start_unix_milliseconds: 1_000,
            end_unix_milliseconds: 3_000,
            resolution: WatchdogProtocolResolution::RawOneSecond,
        },
    )
    .unwrap();
    let unretained = Arc::new(MockDataProvider::with_history_error(
        WatchdogProtocolDataError::RangeNotRetained,
    ));
    let mut sink = RecordingSink::default();
    let result = WatchdogProtocolDispatcher::new(unretained)
        .dispatch(&controller, &range, &mut sink)
        .unwrap();
    assert!(!result.succeeded());
    assert_error(&sink.responses[0], 413, "range exceeds retained history");

    let malformed = Arc::new(MockDataProvider::with_history_batches(vec![vec![sample(
        4,
    )]]));
    let mut sink = RecordingSink::default();
    let result = WatchdogProtocolDispatcher::new(malformed)
        .dispatch(&controller, &range, &mut sink)
        .unwrap();
    assert!(!result.succeeded());
    assert_error(
        &sink.responses[0],
        503,
        "Watchdog telemetry is temporarily unavailable",
    );

    let mut sink = RecordingSink {
        responses: Vec::new(),
        fail: true,
    };
    assert!(
        WatchdogProtocolDispatcher::new(Arc::new(MockDataProvider::ordinary()))
            .dispatch(&controller, &request, &mut sink)
            .is_err()
    );
}

// Composes one manager tick with authenticated partial-frame dispatch and retirement.
#[test]
fn protocol_service_composes_manager_listener_and_controller_registry() {
    let registry = controller_registry();
    let binding = binding('a', '1', 1, 'a', 101);
    let sessions = Arc::new(MockSessions::new(binding.clone()));
    let listener = Arc::new(protocol_listener(
        registry.clone(),
        sessions,
        WatchdogProtocolListenerLimits::new(2, 4, 5_000, 6_000).unwrap(),
    ));
    let manager = Arc::new(
        WatchdogManager::new(
            thresholds(),
            Arc::new(OneSampleProvider),
            Arc::new(NoProtectionProvider),
            Arc::new(MemoryStorageProvider),
        )
        .unwrap(),
    );
    let fanout = Arc::new(WatchdogLiveFanout::new(
        WatchdogLiveFanoutLimits::production(),
    ));
    let service = WatchdogProtocolService::new_with_fanout(manager, listener, fanout.clone());
    assert_eq!(service.tick().unwrap().sample().sequence(), 1);
    assert_eq!(
        fanout.publish(&sample(1)).unwrap().kind(),
        WatchdogLivePublishKind::Replayed
    );

    let input = [
        request_frame(10, WatchdogProtocolRequestKind::Ping { nonce: 77 }),
        request_frame(11, WatchdogProtocolRequestKind::GetLatest),
    ]
    .concat();
    let mut stream = MockAuthenticatedStream::new(input, '1').with_maximum_read(2);
    assert!(matches!(
        service.serve_authenticated_stream(&mut stream).unwrap(),
        WatchdogProtocolConnectionOutcome::Completed
    ));
    assert_eq!(
        *stream.timeouts.lock().unwrap(),
        Some((Duration::from_secs(5), Duration::from_secs(6)))
    );
    let responses = decode_output(&stream.output);
    assert!(matches!(
        responses[0].kind(),
        WatchdogProtocolResponseKind::Pong { nonce: 77 }
    ));
    assert!(matches!(
        responses[1].kind(),
        WatchdogProtocolResponseKind::Latest(sample) if sample.sequence() == 4
    ));
    assert!(registry.active_bindings().unwrap().is_empty());
    assert!(registry
        .apply(binding, registry.revision().unwrap())
        .is_err());
}

// Rejects authentication, replay, malformed, oversized, truncated, and timeout paths.
#[test]
fn protocol_listener_fails_closed_at_every_accepted_stream_boundary() {
    let ordinary_limits = WatchdogProtocolListenerLimits::new(2, 2, 1_000, 1_000).unwrap();

    let registry = controller_registry();
    let sessions = Arc::new(MockSessions::new(binding('a', '1', 1, 'a', 101)));
    let listener = protocol_listener(registry, sessions, ordinary_limits);
    let mut mismatched = MockAuthenticatedStream::new(Vec::new(), '2');
    assert!(listener
        .serve_authenticated_stream(&mut mismatched)
        .is_err());
    assert!(mismatched.output.is_empty());

    let registry = controller_registry();
    let replayed = binding('a', '1', 1, 'a', 101);
    registry
        .apply(replayed.clone(), registry.revision().unwrap())
        .unwrap();
    let listener = protocol_listener(
        registry,
        Arc::new(MockSessions::new(replayed)),
        ordinary_limits,
    );
    let mut stream = MockAuthenticatedStream::new(Vec::new(), '1');
    assert!(listener.serve_authenticated_stream(&mut stream).is_err());

    let malformed_frame = encode_watchdog_protocol_frame(&[0xff]).unwrap();
    let (outcome, responses) = serve_fixture(malformed_frame, ordinary_limits);
    assert!(matches!(
        outcome,
        WatchdogProtocolConnectionOutcome::Completed
    ));
    assert_error(&responses[0], 400, "invalid protobuf request");

    let oversized = vec![0, 1, 0, 1];
    assert!(serve_fixture_error(oversized, ordinary_limits));
    assert!(serve_fixture_error(vec![0, 0, 0, 8, 1, 2], ordinary_limits));

    let registry = controller_registry();
    let listener = protocol_listener(
        registry,
        Arc::new(MockSessions::new(binding('a', '1', 1, 'a', 101))),
        ordinary_limits,
    );
    let mut timeout =
        MockAuthenticatedStream::new(Vec::new(), '1').with_read_error(ErrorKind::TimedOut);
    assert!(listener.serve_authenticated_stream(&mut timeout).is_err());

    let registry = controller_registry();
    let listener = protocol_listener(
        registry,
        Arc::new(MockSessions::new(binding('a', '1', 1, 'a', 101))),
        WatchdogProtocolListenerLimits::new(2, 1, 1_000, 1_000).unwrap(),
    );
    let input = [
        request_frame(1, WatchdogProtocolRequestKind::Ping { nonce: 1 }),
        request_frame(2, WatchdogProtocolRequestKind::Ping { nonce: 2 }),
    ]
    .concat();
    let mut limited = MockAuthenticatedStream::new(input, '1');
    assert!(matches!(
        listener.serve_authenticated_stream(&mut limited).unwrap(),
        WatchdogProtocolConnectionOutcome::Completed
    ));
    assert_eq!(decode_output(&limited.output).len(), 1);
}

// Holds connection and controller bounds for live delivery and rejects superseded sessions.
#[test]
fn protocol_subscription_holds_bounds_and_revalidates_live_identity() {
    let registry = controller_registry();
    let first = binding('a', '1', 1, 'a', 101);
    let sessions = Arc::new(MockSessions::new(first));
    let listener = protocol_listener(
        registry.clone(),
        sessions.clone(),
        WatchdogProtocolListenerLimits::new(1, 2, 1_000, 1_000).unwrap(),
    );
    let mut stream = MockAuthenticatedStream::new(
        request_frame(
            20,
            WatchdogProtocolRequestKind::Subscribe { history_seconds: 0 },
        ),
        '1',
    );
    let subscription = match listener.serve_authenticated_stream(&mut stream).unwrap() {
        WatchdogProtocolConnectionOutcome::Subscribed(subscription) => subscription,
        WatchdogProtocolConnectionOutcome::Completed => panic!("subscription was not retained"),
    };
    assert_eq!(subscription.request_id(), 20);
    assert_eq!(sessions.calls.load(Ordering::Acquire), 1);

    let mut second_stream = MockAuthenticatedStream::new(Vec::new(), '1');
    assert!(listener
        .serve_authenticated_stream(&mut second_stream)
        .is_err());
    assert_eq!(sessions.calls.load(Ordering::Acquire), 1);

    subscription
        .send_live_sample(&mut stream, sample(5))
        .unwrap();
    subscription.send_gap(&mut stream, 6, 8).unwrap();
    let responses = decode_output(&stream.output);
    assert!(matches!(
        responses[2].kind(),
        WatchdogProtocolResponseKind::Live(sample) if sample.sequence() == 5
    ));
    assert!(matches!(
        responses[3].kind(),
        WatchdogProtocolResponseKind::Gap {
            first_missing_sequence: 6,
            latest_sequence: 8
        }
    ));

    let second = binding('a', '1', 2, 'b', 202);
    registry
        .apply(second.clone(), registry.revision().unwrap())
        .unwrap();
    assert!(subscription
        .send_live_sample(&mut stream, sample(9))
        .is_err());
    drop(subscription);
    assert!(registry.is_active(&second).unwrap());

    sessions.replace(second);
    let mut replay = MockAuthenticatedStream::new(Vec::new(), '1');
    assert!(listener.serve_authenticated_stream(&mut replay).is_err());
}

// Revokes existing leases and admits only replacement trust after one atomic registry reload.
#[test]
fn protocol_listener_revalidates_registry_generation_after_reload() {
    let registry = controller_registry();
    let sessions = Arc::new(MockSessions::new(binding('a', '1', 1, 'a', 101)));
    let listener = protocol_listener(
        registry,
        sessions.clone(),
        WatchdogProtocolListenerLimits::new(2, 2, 1_000, 1_000).unwrap(),
    );
    let store = listener.controller_registry_store();
    let mut first_stream = MockAuthenticatedStream::new(
        request_frame(
            25,
            WatchdogProtocolRequestKind::Subscribe { history_seconds: 0 },
        ),
        '1',
    );
    let subscription = match listener
        .serve_authenticated_stream(&mut first_stream)
        .unwrap()
    {
        WatchdogProtocolConnectionOutcome::Subscribed(subscription) => subscription,
        WatchdogProtocolConnectionOutcome::Completed => panic!("subscription was not retained"),
    };
    let source = format!(
        "version=1\ninstallation_id={}\ncontroller={},{}\n",
        "f".repeat(64),
        "b".repeat(32),
        "2".repeat(64)
    );
    store
        .reload(WatchdogControllerAllowlist::parse(source.as_bytes()).unwrap())
        .unwrap();
    assert!(!subscription.is_active().unwrap());
    assert!(subscription
        .send_live_sample(&mut first_stream, sample(9))
        .is_err());
    drop(subscription);

    sessions.replace(binding('b', '2', 1, 'b', 202));
    let mut replacement = MockAuthenticatedStream::new(
        request_frame(26, WatchdogProtocolRequestKind::Ping { nonce: 26 }),
        '2',
    );
    assert!(matches!(
        listener
            .serve_authenticated_stream(&mut replacement)
            .unwrap(),
        WatchdogProtocolConnectionOutcome::Completed
    ));
}

// Enforces the controller registry bound independently from the connection-worker bound.
#[test]
fn protocol_listener_enforces_the_controller_bound_independently() {
    let registry = two_controller_registry();
    let sessions = Arc::new(MockSessions::new(binding('a', '1', 1, 'a', 101)));
    let listener = protocol_listener(
        registry,
        sessions.clone(),
        WatchdogProtocolListenerLimits::new(2, 2, 1_000, 1_000).unwrap(),
    );
    let mut first_stream = MockAuthenticatedStream::new(
        request_frame(
            30,
            WatchdogProtocolRequestKind::Subscribe { history_seconds: 0 },
        ),
        '1',
    );
    let subscription = match listener
        .serve_authenticated_stream(&mut first_stream)
        .unwrap()
    {
        WatchdogProtocolConnectionOutcome::Subscribed(subscription) => subscription,
        WatchdogProtocolConnectionOutcome::Completed => panic!("subscription was not retained"),
    };

    sessions.replace(binding('b', '2', 1, 'b', 202));
    let mut bounded = MockAuthenticatedStream::new(
        request_frame(31, WatchdogProtocolRequestKind::Ping { nonce: 31 }),
        '2',
    );
    assert!(listener.serve_authenticated_stream(&mut bounded).is_err());
    assert!(bounded.output.is_empty());

    drop(subscription);
    let mut admitted = MockAuthenticatedStream::new(
        request_frame(32, WatchdogProtocolRequestKind::Ping { nonce: 32 }),
        '2',
    );
    assert!(matches!(
        listener.serve_authenticated_stream(&mut admitted).unwrap(),
        WatchdogProtocolConnectionOutcome::Completed
    ));
    assert!(matches!(
        decode_output(&admitted.output)[0].kind(),
        WatchdogProtocolResponseKind::Pong { nonce: 32 }
    ));
}

// Reads latest and paged history through the concrete native filesystem adapter.
#[test]
fn protocol_filesystem_adapter_uses_existing_native_storage_contracts() {
    let directory = tempdir().unwrap();
    let storage_root = directory.path().join("watchdog");
    fs::create_dir(&storage_root).unwrap();
    fs::set_permissions(&storage_root, fs::Permissions::from_mode(0o700)).unwrap();
    let storage = Arc::new(
        FilesystemWatchdogStorage::open_with_layout(
            &storage_root,
            WatchdogStorageLayout::new(4, 4, 4).unwrap(),
        )
        .unwrap(),
    );
    for sequence in 1..=3 {
        storage.record_sample(&sample(sequence)).unwrap();
    }
    let provider = FilesystemWatchdogProtocolDataProvider::new(storage, Arc::new(MockIdentity));
    assert_eq!(provider.latest().unwrap().unwrap().sequence(), 3);
    let mut cursor = provider
        .history(WatchdogProtocolResolution::RawOneSecond, 1_000, 3_000)
        .unwrap();
    assert_eq!(cursor.through_sequence(), 3);
    assert_eq!(cursor.next_batch(128).unwrap().unwrap().len(), 3);
    assert!(cursor.next_batch(128).unwrap().is_none());
    assert_eq!(provider.capabilities().unwrap().physical_gpu_count(), 2);
    assert!(provider
        .site_status(&binding('a', '1', 1, 'a', 101))
        .is_ok());
    assert!(matches!(
        provider.history(WatchdogProtocolResolution::RawOneSecond, 0, 86_400_000,),
        Err(WatchdogProtocolDataError::RangeNotRetained)
    ));
}

#[derive(Default)]
struct RecordingSink {
    responses: Vec<WatchdogProtocolResponse>,
    fail: bool,
}

impl WatchdogProtocolResponseSink for RecordingSink {
    // Records one typed response or injects one deterministic sink failure.
    fn send(&mut self, response: WatchdogProtocolResponse) -> Result<(), WatchdogError> {
        if self.fail {
            return Err(WatchdogError::provider("test sink", "write failed"));
        }
        self.responses.push(response);
        Ok(())
    }
}

struct MockHistoryCursor {
    batches: VecDeque<Vec<WatchdogSample>>,
    through_sequence: u64,
}

impl WatchdogProtocolHistoryCursor for MockHistoryCursor {
    // Returns deterministic pre-batched history under the requested protocol bound.
    fn next_batch(
        &mut self,
        maximum_samples: usize,
    ) -> Result<Option<Vec<WatchdogSample>>, WatchdogProtocolDataError> {
        let batch = self.batches.pop_front();
        if batch
            .as_ref()
            .is_some_and(|batch| batch.len() > maximum_samples)
        {
            return Err(WatchdogProtocolDataError::Unavailable);
        }
        Ok(batch)
    }

    // Returns the fixed query-start durable head.
    fn through_sequence(&self) -> u64 {
        self.through_sequence
    }
}

struct MockIdentity;

impl WatchdogProtocolIdentityProvider for MockIdentity {
    // Returns the exact ordinary C timing fixture.
    fn capabilities(&self) -> Result<WatchdogProtocolCapabilities, WatchdogProtocolDataError> {
        Ok(WatchdogProtocolCapabilities::new(1_000, 10_000, 2).unwrap())
    }

    // Returns the same complete public state used by dispatcher tests.
    fn site_status(
        &self,
        binding: &WatchdogControllerBinding,
    ) -> Result<WatchdogProtocolSiteStatus, WatchdogProtocolDataError> {
        MockDataProvider::ordinary().site_status(binding)
    }

    // Returns the same idle-safe resident identity used by dispatcher tests.
    fn resident_status(&self) -> Result<WatchdogProtocolResidentStatus, WatchdogProtocolDataError> {
        MockDataProvider::ordinary().resident_status()
    }
}

struct MockDataProvider {
    latest: Result<Option<WatchdogSample>, WatchdogProtocolDataError>,
    history_error: Option<WatchdogProtocolDataError>,
    history_batches: Vec<Vec<WatchdogSample>>,
}

impl MockDataProvider {
    // Creates the complete ordinary data fixture.
    fn ordinary() -> Self {
        Self {
            latest: Ok(Some(sample(4))),
            history_error: None,
            history_batches: vec![vec![sample(1), sample(2)], vec![sample(3)]],
        }
    }

    // Creates one provider with a closed latest-sample failure.
    fn with_latest_error(error: WatchdogProtocolDataError) -> Self {
        Self {
            latest: Err(error),
            history_error: None,
            history_batches: Vec::new(),
        }
    }

    // Creates one provider with no recorded sample.
    fn without_latest() -> Self {
        Self {
            latest: Ok(None),
            history_error: None,
            history_batches: Vec::new(),
        }
    }

    // Creates one provider with a closed retained-range failure.
    fn with_history_error(error: WatchdogProtocolDataError) -> Self {
        Self {
            latest: Ok(Some(sample(4))),
            history_error: Some(error),
            history_batches: Vec::new(),
        }
    }

    // Creates one provider with caller-selected history batches.
    fn with_history_batches(history_batches: Vec<Vec<WatchdogSample>>) -> Self {
        Self {
            latest: Ok(Some(sample(4))),
            history_error: None,
            history_batches,
        }
    }
}

impl WatchdogProtocolDataProvider for MockDataProvider {
    // Returns the injected latest-sample result.
    fn latest(&self) -> Result<Option<WatchdogSample>, WatchdogProtocolDataError> {
        self.latest.clone()
    }

    // Returns the injected bounded cursor or range failure.
    fn history(
        &self,
        _resolution: WatchdogProtocolResolution,
        _start_unix_milliseconds: u64,
        _end_unix_milliseconds: u64,
    ) -> Result<Box<dyn WatchdogProtocolHistoryCursor>, WatchdogProtocolDataError> {
        if let Some(error) = self.history_error {
            return Err(error);
        }
        Ok(Box::new(MockHistoryCursor {
            batches: self.history_batches.clone().into(),
            through_sequence: 4,
        }))
    }

    // Returns the exact ordinary C timing fixture.
    fn capabilities(&self) -> Result<WatchdogProtocolCapabilities, WatchdogProtocolDataError> {
        Ok(WatchdogProtocolCapabilities::new(1_000, 10_000, 2).unwrap())
    }

    // Returns a complete public state including the valid empty no-container field.
    fn site_status(
        &self,
        _binding: &WatchdogControllerBinding,
    ) -> Result<WatchdogProtocolSiteStatus, WatchdogProtocolDataError> {
        Ok(WatchdogProtocolSiteStatus::new(
            "v0.11.0-rc.99".to_string(),
            "fixture-model".to_string(),
            "dwarfstar".to_string(),
            "fixture-runtime".to_string(),
            "0.11.0-rc.2".to_string(),
            "a".repeat(64),
            "dwarfstar-native".to_string(),
            true,
            8_000,
            64,
            16,
            557_056,
            "running".to_string(),
            "absent".to_string(),
            "none".to_string(),
            false,
            false,
            String::new(),
            "f".repeat(64),
        )
        .unwrap())
    }

    // Returns an idle-safe ready identity without consulting placement state.
    fn resident_status(&self) -> Result<WatchdogProtocolResidentStatus, WatchdogProtocolDataError> {
        Ok(WatchdogProtocolResidentStatus::ready(
            NodeId::parse(&"1".repeat(32)).unwrap(),
            "v0.11.0-rc.99".to_string(),
            Sha256Digest::parse(&"c".repeat(64)).unwrap(),
            InstallationId::parse(&"a".repeat(64)).unwrap(),
        )
        .unwrap())
    }
}

struct MockSessions {
    binding: Mutex<WatchdogControllerBinding>,
    calls: AtomicUsize,
}

impl MockSessions {
    // Creates one mutable exact session fixture.
    fn new(binding: WatchdogControllerBinding) -> Self {
        Self {
            binding: Mutex::new(binding),
            calls: AtomicUsize::new(0),
        }
    }

    // Replaces the future externally resolved controller generation.
    fn replace(&self, binding: WatchdogControllerBinding) {
        *self.binding.lock().unwrap() = binding;
    }
}

impl WatchdogControllerSessionProvider for MockSessions {
    // Returns the injected binding only for its exact certificate fingerprint.
    fn binding_for_certificate(
        &self,
        _certificate_sha256: &str,
    ) -> Result<WatchdogControllerBinding, WatchdogError> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        Ok(self.binding.lock().unwrap().clone())
    }
}

struct MockAuthenticatedStream {
    input: Cursor<Vec<u8>>,
    output: Vec<u8>,
    certificate_sha256: String,
    maximum_read: usize,
    read_error: Option<ErrorKind>,
    timeouts: Mutex<Option<(Duration, Duration)>>,
}

impl MockAuthenticatedStream {
    // Creates one accepted authenticated stream fixture.
    fn new(input: Vec<u8>, certificate: char) -> Self {
        Self {
            input: Cursor::new(input),
            output: Vec::new(),
            certificate_sha256: certificate.to_string().repeat(64),
            maximum_read: usize::MAX,
            read_error: None,
            timeouts: Mutex::new(None),
        }
    }

    // Restricts each native read to exercise partial frame assembly.
    fn with_maximum_read(mut self, maximum_read: usize) -> Self {
        self.maximum_read = maximum_read;
        self
    }

    // Injects one persistent native read failure kind.
    fn with_read_error(mut self, error: ErrorKind) -> Self {
        self.read_error = Some(error);
        self
    }
}

impl Read for MockAuthenticatedStream {
    // Reads injected bytes under the selected partial-read or failure behavior.
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        if let Some(error) = self.read_error {
            return Err(Error::new(error, "injected read failure"));
        }
        let maximum = output.len().min(self.maximum_read);
        self.input.read(&mut output[..maximum])
    }
}

impl Write for MockAuthenticatedStream {
    // Records every complete listener write for framed response verification.
    fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
        self.output.extend_from_slice(input);
        Ok(input.len())
    }

    // Completes the deterministic in-memory write boundary.
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl WatchdogAuthenticatedStream for MockAuthenticatedStream {
    // Returns the injected already-verified TLS leaf digest.
    fn authenticated_certificate_sha256(&self) -> Result<String, WatchdogError> {
        Ok(self.certificate_sha256.clone())
    }

    // Records the exact listener-selected stream deadlines.
    fn configure_timeouts(
        &self,
        read_timeout: Duration,
        write_timeout: Duration,
    ) -> Result<(), WatchdogError> {
        *self.timeouts.lock().unwrap() = Some((read_timeout, write_timeout));
        Ok(())
    }
}

struct OneSampleProvider;

impl WatchdogSampleProvider for OneSampleProvider {
    // Returns the one exact manager-composition sample.
    fn sample(&self, sequence: u64) -> Result<WatchdogSample, WatchdogError> {
        Ok(sample(sequence))
    }
}

struct NoProtectionProvider;

impl WatchdogProtectionProvider for NoProtectionProvider {
    // Returns no protected process for the ordinary composition tick.
    fn observations(
        &self,
        _sample: &WatchdogSample,
    ) -> Result<Vec<WatchdogProtectionObservation>, WatchdogError> {
        Ok(Vec::new())
    }

    // Rejects an unreachable disarm callback in this fixture.
    fn acknowledge_disarmed(&self, _target: &WatchdogProtectedEngine) -> Result<(), WatchdogError> {
        Err(WatchdogError::provider(
            "test protection",
            "unexpected disarm",
        ))
    }

    // Rejects an unreachable trip callback in this fixture.
    fn latch_trip(
        &self,
        _target: &WatchdogProtectedEngine,
        _action: WatchdogSafetyAction,
        _reason: &'static str,
        _input: WatchdogSafetyInput,
    ) -> Result<(), WatchdogError> {
        Err(WatchdogError::provider(
            "test protection",
            "unexpected trip",
        ))
    }

    // Rejects an unreachable containment callback in this fixture.
    fn contain(
        &self,
        _target: &WatchdogProtectedEngine,
        _action: WatchdogSafetyAction,
        _grace_milliseconds: u32,
    ) -> Result<bool, WatchdogError> {
        Err(WatchdogError::provider(
            "test protection",
            "unexpected containment",
        ))
    }
}

struct MemoryStorageProvider;

impl WatchdogStorageProvider for MemoryStorageProvider {
    // Starts the fixture at sequence one.
    fn next_sequence(&self) -> Result<u64, WatchdogError> {
        Ok(1)
    }

    // Accepts the ordinary manager sample.
    fn record_sample(&self, _sample: &WatchdogSample) -> Result<(), WatchdogError> {
        Ok(())
    }

    // Rejects an unreachable safety event in this fixture.
    fn record_event(&self, _event: &WatchdogSafetyEvent) -> Result<(), WatchdogError> {
        Err(WatchdogError::provider("test storage", "unexpected event"))
    }

    // Accepts an ordinary empty flush.
    fn flush(&self) -> Result<(), WatchdogError> {
        Ok(())
    }
}

// Creates one listener over the ordinary provider and injected session boundary.
fn protocol_listener(
    registry: Arc<WatchdogControllerRegistry>,
    sessions: Arc<MockSessions>,
    limits: WatchdogProtocolListenerLimits,
) -> WatchdogProtocolListener {
    WatchdogProtocolListener::new(
        Arc::new(WatchdogProtocolDispatcher::new(Arc::new(
            MockDataProvider::ordinary(),
        ))),
        registry,
        sessions,
        limits,
    )
}

// Serves one ordinary fixture and returns its terminal outcome and responses.
fn serve_fixture(
    input: Vec<u8>,
    limits: WatchdogProtocolListenerLimits,
) -> (
    WatchdogProtocolConnectionOutcome,
    Vec<WatchdogProtocolResponse>,
) {
    let registry = controller_registry();
    let listener = protocol_listener(
        registry,
        Arc::new(MockSessions::new(binding('a', '1', 1, 'a', 101))),
        limits,
    );
    let mut stream = MockAuthenticatedStream::new(input, '1');
    let outcome = listener.serve_authenticated_stream(&mut stream).unwrap();
    (outcome, decode_output(&stream.output))
}

// Returns whether one fixture fails before emitting a public response.
fn serve_fixture_error(input: Vec<u8>, limits: WatchdogProtocolListenerLimits) -> bool {
    let registry = controller_registry();
    let listener = protocol_listener(
        registry,
        Arc::new(MockSessions::new(binding('a', '1', 1, 'a', 101))),
        limits,
    );
    let mut stream = MockAuthenticatedStream::new(input, '1');
    listener.serve_authenticated_stream(&mut stream).is_err() && stream.output.is_empty()
}

// Decodes every concatenated response frame emitted by one mock stream.
fn decode_output(output: &[u8]) -> Vec<WatchdogProtocolResponse> {
    let mut offset = 0;
    let mut responses = Vec::new();
    while offset < output.len() {
        let length = u32::from_be_bytes(output[offset..offset + 4].try_into().unwrap()) as usize;
        let end = offset + 4 + length;
        let payload = decode_watchdog_protocol_frame(&output[offset..end]).unwrap();
        responses.push(decode_watchdog_protocol_response(payload).unwrap());
        offset = end;
    }
    responses
}

// Encodes one complete request frame for an accepted stream fixture.
fn request_frame(request_id: u64, kind: WatchdogProtocolRequestKind) -> Vec<u8> {
    let request = WatchdogProtocolRequest::new(request_id, kind).unwrap();
    encode_watchdog_protocol_frame(&encode_watchdog_protocol_request(&request).unwrap()).unwrap()
}

// Requires one exact redacted error code and public message.
fn assert_error(response: &WatchdogProtocolResponse, code: u32, message: &str) {
    assert!(matches!(
        response.kind(),
        WatchdogProtocolResponseKind::Error {
            code: actual_code,
            message: actual_message
        } if *actual_code == code && actual_message == message
    ));
}

// Creates one complete sample on a fixed one-second timeline.
fn sample(sequence: u64) -> WatchdogSample {
    WatchdogSample::new(sequence, sequence * 1_000, sequence * 1_000).unwrap()
}

// Creates one exact version-one controller registry.
fn controller_registry() -> Arc<WatchdogControllerRegistry> {
    let source = format!(
        "version=1\ninstallation_id={}\ncontroller={},{}\n",
        "f".repeat(64),
        "a".repeat(32),
        "1".repeat(64)
    );
    Arc::new(
        WatchdogControllerRegistry::new(
            WatchdogControllerAllowlist::parse(source.as_bytes()).unwrap(),
            1,
        )
        .unwrap(),
    )
}

// Creates a two-controller allowlist with a one-controller active-session bound.
fn two_controller_registry() -> Arc<WatchdogControllerRegistry> {
    let source = format!(
        "version=1\ninstallation_id={}\ncontroller={},{}\ncontroller={},{}\n",
        "f".repeat(64),
        "a".repeat(32),
        "1".repeat(64),
        "b".repeat(32),
        "2".repeat(64)
    );
    Arc::new(
        WatchdogControllerRegistry::new(
            WatchdogControllerAllowlist::parse(source.as_bytes()).unwrap(),
            1,
        )
        .unwrap(),
    )
}

// Creates one exact authenticated controller and protected-process binding.
fn binding(
    controller: char,
    fingerprint: char,
    session_generation: u64,
    target_generation: char,
    process_id: u32,
) -> WatchdogControllerBinding {
    WatchdogControllerBinding::new(
        &controller.to_string().repeat(32),
        &fingerprint.to_string().repeat(64),
        session_generation,
        protected_target(target_generation, process_id),
    )
    .unwrap()
}

// Creates one exact active process descriptor for a controller session.
fn protected_target(generation: char, process_id: u32) -> WatchdogProtectedEngine {
    WatchdogProtectedEngine::parse(&format!(
        "version=1\ngeneration={}\nphase=armed\ncontainer_name=container-{generation}\ncontainer_id={}\npid={process_id}\nstart_ticks={}\nboot_id=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\ncgroup=/sys/fs/cgroup/letsinfer/{process_id}\n",
        generation.to_string().repeat(32),
        generation.to_string().repeat(64),
        u64::from(process_id) * 10,
    ))
    .unwrap()
}

// Creates one valid deterministic safety threshold fixture.
fn thresholds() -> WatchdogSafetyThresholds {
    WatchdogSafetyThresholds::new(400, 300, 200, 100, 10, 20, 3, 1_000).unwrap()
}
