// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use li_watchdog_manager::{
    WatchdogError, WatchdogLiveClock, WatchdogLiveDrainState, WatchdogLiveFanout,
    WatchdogLiveFanoutLimits, WatchdogLivePublishKind, WatchdogLiveRunControl, WatchdogLiveSink,
    WatchdogLiveWake, WatchdogSample,
};

// Records typed deliveries without performing network I/O.
#[derive(Clone, Debug, Eq, PartialEq)]
enum SinkEvent {
    Sample(u64),
    Gap(u64, u64),
}

// Supplies deterministic wake counts and optional native failure.
struct MockWake {
    wake_count: AtomicUsize,
    wait_count: AtomicUsize,
    fail_wake: bool,
    stop_on_wait: Option<Arc<AtomicBool>>,
}

impl MockWake {
    // Creates one ordinary nonblocking wake fixture.
    fn ordinary() -> Self {
        Self {
            wake_count: AtomicUsize::new(0),
            wait_count: AtomicUsize::new(0),
            fail_wake: false,
            stop_on_wait: None,
        }
    }

    // Creates one wake capability that fails publication notification.
    fn failing() -> Self {
        Self {
            fail_wake: true,
            ..Self::ordinary()
        }
    }

    // Creates one wait capability that requests loop shutdown deterministically.
    fn stopping(control: Arc<AtomicBool>) -> Self {
        Self {
            stop_on_wait: Some(control),
            ..Self::ordinary()
        }
    }
}

impl WatchdogLiveWake for MockWake {
    // Records one notification or injects one deterministic failure.
    fn wake(&self) -> Result<(), WatchdogError> {
        self.wake_count.fetch_add(1, Ordering::AcqRel);
        if self.fail_wake {
            Err(WatchdogError::provider("test wake", "wake failed"))
        } else {
            Ok(())
        }
    }

    // Records one bounded wait and optionally requests loop shutdown.
    fn wait(&self, _maximum_duration: Duration) -> Result<(), WatchdogError> {
        self.wait_count.fetch_add(1, Ordering::AcqRel);
        if let Some(control) = &self.stop_on_wait {
            control.store(true, Ordering::Release);
        }
        Ok(())
    }
}

// Supplies caller-controlled monotonic time to slow-sink tests.
struct MockClock {
    milliseconds: AtomicU64,
}

impl MockClock {
    // Creates one clock at deterministic process-local zero.
    fn new() -> Self {
        Self {
            milliseconds: AtomicU64::new(0),
        }
    }

    // Advances monotonic time by one exact interval.
    fn advance(&self, milliseconds: u64) {
        self.milliseconds.fetch_add(milliseconds, Ordering::AcqRel);
    }
}

impl WatchdogLiveClock for MockClock {
    // Returns the injected monotonic millisecond value.
    fn monotonic_milliseconds(&self) -> Result<u64, WatchdogError> {
        Ok(self.milliseconds.load(Ordering::Acquire))
    }
}

// Records successful events and injects authorization, send, or duration behavior.
struct MockSink {
    authorized: bool,
    fail_send: bool,
    advance_milliseconds: u64,
    clock: Arc<MockClock>,
    events: Vec<SinkEvent>,
    authorization_count: AtomicUsize,
}

impl MockSink {
    // Creates one authorized immediate deterministic sink.
    fn ordinary(clock: Arc<MockClock>) -> Self {
        Self {
            authorized: true,
            fail_send: false,
            advance_milliseconds: 0,
            clock,
            events: Vec::new(),
            authorization_count: AtomicUsize::new(0),
        }
    }
}

impl WatchdogLiveSink for MockSink {
    // Returns the injected current lease judgment and records every revalidation.
    fn is_authorized(&self) -> Result<bool, WatchdogError> {
        self.authorization_count.fetch_add(1, Ordering::AcqRel);
        Ok(self.authorized)
    }

    // Records one sample after applying the injected send behavior.
    fn send_sample(&mut self, sample: WatchdogSample) -> Result<(), WatchdogError> {
        self.clock.advance(self.advance_milliseconds);
        if self.fail_send {
            return Err(WatchdogError::provider("test sink", "send failed"));
        }
        self.events.push(SinkEvent::Sample(sample.sequence()));
        Ok(())
    }

    // Records one gap after applying the injected send behavior.
    fn send_gap(
        &mut self,
        first_missing_sequence: u64,
        latest_sequence: u64,
    ) -> Result<(), WatchdogError> {
        self.clock.advance(self.advance_milliseconds);
        if self.fail_send {
            return Err(WatchdogError::provider("test sink", "send failed"));
        }
        self.events
            .push(SinkEvent::Gap(first_missing_sequence, latest_sequence));
        Ok(())
    }
}

// Supplies one atomic shutdown decision to the resident receiver loop.
struct MockControl {
    stopped: Arc<AtomicBool>,
}

impl WatchdogLiveRunControl for MockControl {
    // Returns the injected terminal loop state.
    fn should_stop(&self) -> bool {
        self.stopped.load(Ordering::Acquire)
    }
}

// Proves ordinary samples are delivered once and each drain obeys its work bound.
#[test]
fn live_fanout_delivers_each_new_sequence_once_under_bounded_work() {
    let fanout = WatchdogLiveFanout::new(limits(2, 4, 1, 10));
    let wake = Arc::new(MockWake::ordinary());
    let mut receiver = fanout.subscribe(wake.clone()).unwrap();
    let clock = Arc::new(MockClock::new());
    let mut sink = MockSink::ordinary(clock.clone());

    assert_eq!(
        fanout.publish(&sample(1)).unwrap().kind(),
        WatchdogLivePublishKind::Published
    );
    assert_eq!(
        fanout.publish(&sample(1)).unwrap().kind(),
        WatchdogLivePublishKind::Replayed
    );
    fanout.publish(&sample(2)).unwrap();
    assert_eq!(wake.wake_count.load(Ordering::Acquire), 2);

    let first = receiver
        .deliver_available(&mut sink, clock.as_ref())
        .unwrap();
    assert_eq!(first.state(), WatchdogLiveDrainState::MoreWork);
    assert_eq!(first.delivery_count(), 1);
    let second = receiver
        .deliver_available(&mut sink, clock.as_ref())
        .unwrap();
    assert_eq!(second.state(), WatchdogLiveDrainState::Idle);
    assert_eq!(second.delivery_count(), 1);
    assert_eq!(
        sink.events,
        vec![SinkEvent::Sample(1), SinkEvent::Sample(2)]
    );
    assert_eq!(sink.authorization_count.load(Ordering::Acquire), 2);
}

// Proves queue overflow and source jumps become explicit ordered gaps before the newest sample.
#[test]
fn live_fanout_collapses_backlog_and_source_discontinuity_into_gaps() {
    let fanout = WatchdogLiveFanout::new(limits(1, 2, 8, 10));
    let mut receiver = fanout.subscribe(Arc::new(MockWake::ordinary())).unwrap();
    let clock = Arc::new(MockClock::new());
    let mut sink = MockSink::ordinary(clock.clone());

    fanout.publish(&sample(1)).unwrap();
    fanout.publish(&sample(2)).unwrap();
    let overflow = fanout.publish(&sample(3)).unwrap();
    assert_eq!(overflow.gap_count(), 1);
    receiver
        .deliver_available(&mut sink, clock.as_ref())
        .unwrap();
    assert_eq!(
        sink.events,
        vec![SinkEvent::Gap(1, 2), SinkEvent::Sample(3)]
    );

    let discontinuity = fanout.publish(&sample(6)).unwrap();
    assert_eq!(discontinuity.gap_count(), 1);
    receiver
        .deliver_available(&mut sink, clock.as_ref())
        .unwrap();
    assert_eq!(
        sink.events,
        vec![
            SinkEvent::Gap(1, 2),
            SinkEvent::Sample(3),
            SinkEvent::Gap(4, 5),
            SinkEvent::Sample(6),
        ]
    );
}

// Proves slow, failed, revoked, and unwakeable subscribers close independently.
#[test]
fn live_fanout_isolates_every_terminal_subscriber_failure() {
    let fanout = WatchdogLiveFanout::new(limits(4, 4, 4, 10));
    let clock = Arc::new(MockClock::new());

    let mut slow = fanout.subscribe(Arc::new(MockWake::ordinary())).unwrap();
    fanout.publish(&sample(1)).unwrap();
    let mut slow_sink = MockSink::ordinary(clock.clone());
    slow_sink.advance_milliseconds = 11;
    assert!(slow
        .deliver_available(&mut slow_sink, clock.as_ref())
        .is_err());
    assert_eq!(fanout.subscriber_count().unwrap(), 0);

    let mut failed = fanout.subscribe(Arc::new(MockWake::ordinary())).unwrap();
    fanout.publish(&sample(2)).unwrap();
    let mut failed_sink = MockSink::ordinary(clock.clone());
    failed_sink.fail_send = true;
    assert!(failed
        .deliver_available(&mut failed_sink, clock.as_ref())
        .is_err());
    assert_eq!(fanout.subscriber_count().unwrap(), 0);

    let mut revoked = fanout.subscribe(Arc::new(MockWake::ordinary())).unwrap();
    fanout.publish(&sample(3)).unwrap();
    let mut revoked_sink = MockSink::ordinary(clock.clone());
    revoked_sink.authorized = false;
    let closed = revoked
        .deliver_available(&mut revoked_sink, clock.as_ref())
        .unwrap();
    assert_eq!(closed.state(), WatchdogLiveDrainState::Closed);
    assert!(revoked_sink.events.is_empty());
    assert_eq!(fanout.subscriber_count().unwrap(), 0);

    let _unwakeable = fanout.subscribe(Arc::new(MockWake::failing())).unwrap();
    let publication = fanout.publish(&sample(4)).unwrap();
    assert_eq!(publication.closed_count(), 1);
    assert_eq!(publication.subscriber_count(), 0);
}

// Proves the resident loop uses injected wake/control and closes on terminal ownership.
#[test]
fn live_receiver_waits_without_spinning_and_closes_on_shutdown() {
    let fanout = WatchdogLiveFanout::new(limits(1, 2, 2, 10));
    let stopped = Arc::new(AtomicBool::new(false));
    let wake = Arc::new(MockWake::stopping(stopped.clone()));
    let mut receiver = fanout.subscribe(wake.clone()).unwrap();
    let clock = Arc::new(MockClock::new());
    let mut sink = MockSink::ordinary(clock.clone());
    let control = MockControl { stopped };

    receiver.serve(&mut sink, clock.as_ref(), &control).unwrap();

    assert_eq!(wake.wait_count.load(Ordering::Acquire), 1);
    assert_eq!(fanout.subscriber_count().unwrap(), 0);
}

// Creates one small explicit fanout policy for deterministic tests.
fn limits(
    maximum_subscribers: usize,
    maximum_backlog: usize,
    maximum_work_per_wake: usize,
    send_timeout_milliseconds: u64,
) -> WatchdogLiveFanoutLimits {
    WatchdogLiveFanoutLimits::new(
        maximum_subscribers,
        maximum_backlog,
        maximum_work_per_wake,
        1,
        send_timeout_milliseconds,
    )
    .unwrap()
}

// Creates one complete sample on the exact resident one-second timeline.
fn sample(sequence: u64) -> WatchdogSample {
    WatchdogSample::new(sequence, sequence * 1_000, sequence * 1_000).unwrap()
}
