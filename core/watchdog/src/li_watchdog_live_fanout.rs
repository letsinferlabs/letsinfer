// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::time::{Duration, Instant};

use crate::{WatchdogError, WatchdogSample};

const WATCHDOG_LIVE_MAX_SUBSCRIBERS: usize = 16;
const WATCHDOG_LIVE_MAX_BACKLOG: usize = 128;
const WATCHDOG_LIVE_MAX_WORK_PER_WAKE: usize = 128;
const WATCHDOG_LIVE_MAX_POLL_MILLISECONDS: u64 = 100;
const WATCHDOG_LIVE_MAX_SEND_MILLISECONDS: u64 = 30_000;

// Defines subscriber, backlog, work, wait, and send bounds for resident fanout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WatchdogLiveFanoutLimits {
    maximum_subscribers: usize,
    maximum_backlog: usize,
    maximum_work_per_wake: usize,
    poll_milliseconds: u64,
    send_timeout_milliseconds: u64,
}

impl WatchdogLiveFanoutLimits {
    // Creates one complete fanout policy inside the native protocol bounds.
    pub fn new(
        maximum_subscribers: usize,
        maximum_backlog: usize,
        maximum_work_per_wake: usize,
        poll_milliseconds: u64,
        send_timeout_milliseconds: u64,
    ) -> Result<Self, WatchdogError> {
        if maximum_subscribers == 0
            || maximum_subscribers > WATCHDOG_LIVE_MAX_SUBSCRIBERS
            || !(2..=WATCHDOG_LIVE_MAX_BACKLOG).contains(&maximum_backlog)
            || maximum_work_per_wake == 0
            || maximum_work_per_wake > WATCHDOG_LIVE_MAX_WORK_PER_WAKE
            || poll_milliseconds == 0
            || poll_milliseconds > WATCHDOG_LIVE_MAX_POLL_MILLISECONDS
            || send_timeout_milliseconds == 0
            || send_timeout_milliseconds > WATCHDOG_LIVE_MAX_SEND_MILLISECONDS
        {
            return Err(fanout_error("live fanout limits are invalid"));
        }
        Ok(Self {
            maximum_subscribers,
            maximum_backlog,
            maximum_work_per_wake,
            poll_milliseconds,
            send_timeout_milliseconds,
        })
    }

    // Returns the explicit native production fanout policy.
    pub fn production() -> Self {
        Self {
            maximum_subscribers: WATCHDOG_LIVE_MAX_SUBSCRIBERS,
            maximum_backlog: 16,
            maximum_work_per_wake: 16,
            poll_milliseconds: 100,
            send_timeout_milliseconds: WATCHDOG_LIVE_MAX_SEND_MILLISECONDS,
        }
    }
}

impl Default for WatchdogLiveFanoutLimits {
    // Supplies the closed production policy without discovering environment values.
    fn default() -> Self {
        Self::production()
    }
}

// Wakes one subscriber worker without giving fanout ownership of its thread.
pub trait WatchdogLiveWake: Send + Sync {
    // Signals newly queued work without waiting for the subscriber.
    fn wake(&self) -> Result<(), WatchdogError>;

    // Waits no longer than the caller's bounded poll interval.
    fn wait(&self, maximum_duration: Duration) -> Result<(), WatchdogError>;
}

// Supplies monotonic time only for enforcing a completed sink-send deadline.
pub trait WatchdogLiveClock: Send + Sync {
    // Returns a nondecreasing process-local millisecond value.
    fn monotonic_milliseconds(&self) -> Result<u64, WatchdogError>;
}

// Reports whether one resident subscriber worker must terminate.
pub trait WatchdogLiveRunControl: Send + Sync {
    // Returns true only after the owning listener begins shutdown.
    fn should_stop(&self) -> bool;
}

// Delivers typed live events through one already-authenticated controller stream.
pub trait WatchdogLiveSink {
    // Revalidates the exact certificate digest and controller generation.
    fn is_authorized(&self) -> Result<bool, WatchdogError>;

    // Sends one exact newly committed sample.
    fn send_sample(&mut self, sample: WatchdogSample) -> Result<(), WatchdogError>;

    // Sends one explicit range for samples removed by a bounded backlog.
    fn send_gap(
        &mut self,
        first_missing_sequence: u64,
        latest_sequence: u64,
    ) -> Result<(), WatchdogError>;
}

// Implements wake coalescing with one mutex generation and condition variable.
pub struct SystemWatchdogLiveWake {
    generation: Mutex<u64>,
    condition: Condvar,
}

impl SystemWatchdogLiveWake {
    // Creates one idle process-local subscriber wake capability.
    pub fn new() -> Self {
        Self {
            generation: Mutex::new(0),
            condition: Condvar::new(),
        }
    }
}

impl Default for SystemWatchdogLiveWake {
    // Creates the ordinary idle wake state.
    fn default() -> Self {
        Self::new()
    }
}

impl WatchdogLiveWake for SystemWatchdogLiveWake {
    // Advances the wake generation and notifies one subscriber worker.
    fn wake(&self) -> Result<(), WatchdogError> {
        let mut generation = self
            .generation
            .lock()
            .map_err(|_| WatchdogError::StateUnavailable)?;
        *generation = generation
            .checked_add(1)
            .ok_or_else(|| fanout_error("live wake generation is exhausted"))?;
        self.condition.notify_one();
        Ok(())
    }

    // Waits until the generation changes or the bounded poll duration expires.
    fn wait(&self, maximum_duration: Duration) -> Result<(), WatchdogError> {
        let generation = self
            .generation
            .lock()
            .map_err(|_| WatchdogError::StateUnavailable)?;
        let observed = *generation;
        let _guard = self
            .condition
            .wait_timeout_while(generation, maximum_duration, |value| *value == observed)
            .map_err(|_| WatchdogError::StateUnavailable)?;
        Ok(())
    }
}

// Supplies process-local monotonic time from one fixed origin.
pub struct SystemWatchdogLiveClock {
    origin: Instant,
}

impl SystemWatchdogLiveClock {
    // Creates one monotonic clock with a process-local zero point.
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for SystemWatchdogLiveClock {
    // Creates the ordinary process-local clock.
    fn default() -> Self {
        Self::new()
    }
}

impl WatchdogLiveClock for SystemWatchdogLiveClock {
    // Returns elapsed milliseconds without exposing wall-clock identity.
    fn monotonic_milliseconds(&self) -> Result<u64, WatchdogError> {
        u64::try_from(self.origin.elapsed().as_millis())
            .map_err(|_| fanout_error("live monotonic clock is exhausted"))
    }
}

// Identifies whether one publication was new or an exact sequence replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchdogLivePublishKind {
    Published,
    Replayed,
}

// Reports bounded publication effects without exposing subscriber identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WatchdogLivePublish {
    kind: WatchdogLivePublishKind,
    subscriber_count: usize,
    gap_count: usize,
    closed_count: usize,
}

impl WatchdogLivePublish {
    // Returns whether the sequence was published or suppressed as a replay.
    pub const fn kind(self) -> WatchdogLivePublishKind {
        self.kind
    }

    // Returns how many current subscribers retained the publication.
    pub const fn subscriber_count(self) -> usize {
        self.subscriber_count
    }

    // Returns how many subscriber backlogs were collapsed into an explicit gap.
    pub const fn gap_count(self) -> usize {
        self.gap_count
    }

    // Returns how many failed wake capabilities were closed.
    pub const fn closed_count(self) -> usize {
        self.closed_count
    }
}

// Identifies the bounded state after one subscriber drain pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchdogLiveDrainState {
    Idle,
    MoreWork,
    Closed,
}

// Reports one bounded subscriber drain without leaking its identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WatchdogLiveDrain {
    state: WatchdogLiveDrainState,
    delivery_count: usize,
}

impl WatchdogLiveDrain {
    // Returns whether the subscriber is idle, still queued, or terminal.
    pub const fn state(self) -> WatchdogLiveDrainState {
        self.state
    }

    // Returns the exact number of sink writes completed in this pass.
    pub const fn delivery_count(self) -> usize {
        self.delivery_count
    }
}

// Owns bounded nonblocking publication to every current subscriber mailbox.
pub struct WatchdogLiveFanout {
    limits: WatchdogLiveFanoutLimits,
    state: Arc<Mutex<WatchdogLiveFanoutState>>,
}

impl WatchdogLiveFanout {
    // Creates one empty resident fanout under an explicit closed policy.
    pub fn new(limits: WatchdogLiveFanoutLimits) -> Self {
        Self {
            limits,
            state: Arc::new(Mutex::new(WatchdogLiveFanoutState {
                closed: false,
                last_published_sequence: 0,
                next_subscriber_id: 1,
                subscribers: BTreeMap::new(),
            })),
        }
    }

    // Registers one future-only subscriber without replaying an implicit stale sample.
    pub fn subscribe(
        &self,
        wake: Arc<dyn WatchdogLiveWake>,
    ) -> Result<WatchdogLiveReceiver, WatchdogError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| WatchdogError::StateUnavailable)?;
        if state.closed {
            return Err(fanout_error("live fanout is closed"));
        }
        if state.subscribers.len() >= self.limits.maximum_subscribers {
            return Err(fanout_error("live subscriber bound was reached"));
        }
        let subscriber_id = state.next_subscriber_id;
        state.next_subscriber_id = state
            .next_subscriber_id
            .checked_add(1)
            .ok_or_else(|| fanout_error("live subscriber identity is exhausted"))?;
        let mailbox = Arc::new(WatchdogLiveMailbox {
            wake,
            state: Mutex::new(WatchdogLiveMailboxState {
                closed: false,
                acknowledged_through: state.last_published_sequence,
                enqueued_through: state.last_published_sequence,
                in_flight: None,
                queue: VecDeque::with_capacity(self.limits.maximum_backlog),
            }),
        });
        state.subscribers.insert(subscriber_id, mailbox.clone());
        Ok(WatchdogLiveReceiver {
            subscriber_id,
            limits: self.limits,
            owner: Arc::downgrade(&self.state),
            mailbox,
            closed: false,
        })
    }

    // Publishes one new committed sequence without performing subscriber network I/O.
    pub fn publish(&self, sample: &WatchdogSample) -> Result<WatchdogLivePublish, WatchdogError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| WatchdogError::StateUnavailable)?;
        if state.closed {
            return Err(fanout_error("live fanout is closed"));
        }
        if sample.sequence() < state.last_published_sequence {
            return Err(fanout_error("live sample sequence is stale"));
        }
        if sample.sequence() == state.last_published_sequence {
            return Ok(WatchdogLivePublish {
                kind: WatchdogLivePublishKind::Replayed,
                subscriber_count: state.subscribers.len(),
                gap_count: 0,
                closed_count: 0,
            });
        }
        let mut gap_count = 0;
        let mut closed = Vec::new();
        for (subscriber_id, mailbox) in &state.subscribers {
            let gap_created = enqueue_sample(mailbox, sample, self.limits.maximum_backlog)?;
            gap_count += usize::from(gap_created);
            if mailbox.wake.wake().is_err() {
                close_mailbox(mailbox);
                closed.push(*subscriber_id);
            }
        }
        for subscriber_id in &closed {
            state.subscribers.remove(subscriber_id);
        }
        state.last_published_sequence = sample.sequence();
        Ok(WatchdogLivePublish {
            kind: WatchdogLivePublishKind::Published,
            subscriber_count: state.subscribers.len(),
            gap_count,
            closed_count: closed.len(),
        })
    }

    // Closes every mailbox and wakes workers before dropping fanout ownership.
    pub fn close(&self) -> Result<(), WatchdogError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| WatchdogError::StateUnavailable)?;
        if state.closed {
            return Ok(());
        }
        state.closed = true;
        let mailboxes = state.subscribers.values().cloned().collect::<Vec<_>>();
        state.subscribers.clear();
        drop(state);
        for mailbox in mailboxes {
            close_mailbox(&mailbox);
            let _ = mailbox.wake.wake();
        }
        Ok(())
    }

    // Returns the exact number of currently registered subscriber mailboxes.
    pub fn subscriber_count(&self) -> Result<usize, WatchdogError> {
        self.state
            .lock()
            .map(|state| state.subscribers.len())
            .map_err(|_| WatchdogError::StateUnavailable)
    }
}

// Owns one subscriber mailbox and its symmetric fanout registration.
pub struct WatchdogLiveReceiver {
    subscriber_id: u64,
    limits: WatchdogLiveFanoutLimits,
    owner: Weak<Mutex<WatchdogLiveFanoutState>>,
    mailbox: Arc<WatchdogLiveMailbox>,
    closed: bool,
}

impl WatchdogLiveReceiver {
    // Drains at most one configured work batch and revalidates before every sink write.
    pub fn deliver_available(
        &mut self,
        sink: &mut dyn WatchdogLiveSink,
        clock: &dyn WatchdogLiveClock,
    ) -> Result<WatchdogLiveDrain, WatchdogError> {
        if self.closed || is_mailbox_closed(&self.mailbox)? {
            self.close();
            return Ok(WatchdogLiveDrain {
                state: WatchdogLiveDrainState::Closed,
                delivery_count: 0,
            });
        }
        let mut delivery_count = 0;
        for _ in 0..self.limits.maximum_work_per_wake {
            if !sink.is_authorized()? {
                self.close();
                return Ok(WatchdogLiveDrain {
                    state: WatchdogLiveDrainState::Closed,
                    delivery_count,
                });
            }
            let Some(delivery) = take_delivery(&self.mailbox)? else {
                return Ok(WatchdogLiveDrain {
                    state: WatchdogLiveDrainState::Idle,
                    delivery_count,
                });
            };
            let began = clock.monotonic_milliseconds()?;
            let result = match &delivery {
                WatchdogLiveDelivery::Sample(sample) => sink.send_sample(sample.clone()),
                WatchdogLiveDelivery::Gap {
                    first_missing_sequence,
                    latest_sequence,
                } => sink.send_gap(*first_missing_sequence, *latest_sequence),
            };
            let completed = clock.monotonic_milliseconds()?;
            if let Err(error) = result {
                self.close();
                return Err(error);
            }
            if completed.saturating_sub(began) > self.limits.send_timeout_milliseconds {
                self.close();
                return Err(fanout_error("live subscriber send timed out"));
            }
            acknowledge_delivery(&self.mailbox, &delivery)?;
            delivery_count += 1;
        }
        let state = if has_queued_delivery(&self.mailbox)? {
            WatchdogLiveDrainState::MoreWork
        } else {
            WatchdogLiveDrainState::Idle
        };
        Ok(WatchdogLiveDrain {
            state,
            delivery_count,
        })
    }

    // Runs one subscriber until shutdown, revocation, sink failure, or fanout closure.
    pub fn serve(
        &mut self,
        sink: &mut dyn WatchdogLiveSink,
        clock: &dyn WatchdogLiveClock,
        control: &dyn WatchdogLiveRunControl,
    ) -> Result<(), WatchdogError> {
        while !control.should_stop() {
            let drain = self.deliver_available(sink, clock)?;
            match drain.state() {
                WatchdogLiveDrainState::Closed => return Ok(()),
                WatchdogLiveDrainState::Idle => self
                    .mailbox
                    .wake
                    .wait(Duration::from_millis(self.limits.poll_milliseconds))?,
                WatchdogLiveDrainState::MoreWork => {
                    self.mailbox.wake.wait(Duration::ZERO)?;
                }
            }
        }
        self.close();
        Ok(())
    }

    // Closes and unregisters this exact mailbox idempotently.
    pub fn close(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        close_mailbox(&self.mailbox);
        if let Some(owner) = self.owner.upgrade() {
            if let Ok(mut state) = owner.lock() {
                state.subscribers.remove(&self.subscriber_id);
            }
        }
    }
}

impl Drop for WatchdogLiveReceiver {
    // Releases the mailbox registration on every worker exit.
    fn drop(&mut self) {
        self.close();
    }
}

// Stores global publication identity and bounded subscriber mailboxes.
struct WatchdogLiveFanoutState {
    closed: bool,
    last_published_sequence: u64,
    next_subscriber_id: u64,
    subscribers: BTreeMap<u64, Arc<WatchdogLiveMailbox>>,
}

// Owns one queue and wake capability without holding either across sink I/O.
struct WatchdogLiveMailbox {
    wake: Arc<dyn WatchdogLiveWake>,
    state: Mutex<WatchdogLiveMailboxState>,
}

// Tracks queued, in-flight, and acknowledged sequences for one subscriber.
struct WatchdogLiveMailboxState {
    closed: bool,
    acknowledged_through: u64,
    enqueued_through: u64,
    in_flight: Option<WatchdogLiveDelivery>,
    queue: VecDeque<WatchdogLiveDelivery>,
}

// Describes one exact sample or one explicit sequence gap.
#[derive(Clone, Debug, Eq, PartialEq)]
enum WatchdogLiveDelivery {
    Sample(WatchdogSample),
    Gap {
        first_missing_sequence: u64,
        latest_sequence: u64,
    },
}

impl WatchdogLiveDelivery {
    // Returns the final sequence reserved or acknowledged by this delivery.
    fn through_sequence(&self) -> u64 {
        match self {
            Self::Sample(sample) => sample.sequence(),
            Self::Gap {
                latest_sequence, ..
            } => *latest_sequence,
        }
    }
}

// Queues one sample or collapses stale backlog into one gap and the newest sample.
fn enqueue_sample(
    mailbox: &WatchdogLiveMailbox,
    sample: &WatchdogSample,
    maximum_backlog: usize,
) -> Result<bool, WatchdogError> {
    let mut state = mailbox
        .state
        .lock()
        .map_err(|_| WatchdogError::StateUnavailable)?;
    if state.closed {
        return Ok(false);
    }
    if sample.sequence() <= state.enqueued_through {
        return Err(fanout_error("subscriber sample sequence is stale"));
    }
    let needs_gap = sample.sequence() > state.enqueued_through.saturating_add(1);
    let required = 1 + usize::from(needs_gap);
    let mut collapsed = false;
    if state.queue.len().saturating_add(required) > maximum_backlog {
        let reserved_through = state
            .in_flight
            .as_ref()
            .map(WatchdogLiveDelivery::through_sequence)
            .unwrap_or(state.acknowledged_through)
            .max(state.acknowledged_through);
        state.queue.clear();
        if sample.sequence() > reserved_through.saturating_add(1) {
            state.queue.push_back(WatchdogLiveDelivery::Gap {
                first_missing_sequence: reserved_through + 1,
                latest_sequence: sample.sequence() - 1,
            });
            collapsed = true;
        }
    } else if needs_gap {
        let first_missing_sequence = state.enqueued_through + 1;
        state.queue.push_back(WatchdogLiveDelivery::Gap {
            first_missing_sequence,
            latest_sequence: sample.sequence() - 1,
        });
        collapsed = true;
    }
    state
        .queue
        .push_back(WatchdogLiveDelivery::Sample(sample.clone()));
    state.enqueued_through = sample.sequence();
    Ok(collapsed)
}

// Moves one queued delivery into the exclusive in-flight slot.
fn take_delivery(
    mailbox: &WatchdogLiveMailbox,
) -> Result<Option<WatchdogLiveDelivery>, WatchdogError> {
    let mut state = mailbox
        .state
        .lock()
        .map_err(|_| WatchdogError::StateUnavailable)?;
    if state.closed {
        return Ok(None);
    }
    if state.in_flight.is_some() {
        return Err(fanout_error("live subscriber already has in-flight work"));
    }
    let delivery = state.queue.pop_front();
    state.in_flight = delivery.clone();
    Ok(delivery)
}

// Commits one successful in-flight delivery without accepting a reordered acknowledgement.
fn acknowledge_delivery(
    mailbox: &WatchdogLiveMailbox,
    delivery: &WatchdogLiveDelivery,
) -> Result<(), WatchdogError> {
    let mut state = mailbox
        .state
        .lock()
        .map_err(|_| WatchdogError::StateUnavailable)?;
    if state.in_flight.as_ref() != Some(delivery)
        || delivery.through_sequence() <= state.acknowledged_through
    {
        return Err(fanout_error("live delivery acknowledgement conflicts"));
    }
    state.acknowledged_through = delivery.through_sequence();
    state.in_flight = None;
    Ok(())
}

// Returns whether one open mailbox still owns queued work.
fn has_queued_delivery(mailbox: &WatchdogLiveMailbox) -> Result<bool, WatchdogError> {
    mailbox
        .state
        .lock()
        .map(|state| !state.closed && !state.queue.is_empty())
        .map_err(|_| WatchdogError::StateUnavailable)
}

// Returns whether one mailbox has reached a terminal state.
fn is_mailbox_closed(mailbox: &WatchdogLiveMailbox) -> Result<bool, WatchdogError> {
    mailbox
        .state
        .lock()
        .map(|state| state.closed)
        .map_err(|_| WatchdogError::StateUnavailable)
}

// Marks one mailbox terminal and discards every undelivered or in-flight value.
fn close_mailbox(mailbox: &WatchdogLiveMailbox) {
    if let Ok(mut state) = mailbox.state.lock() {
        state.closed = true;
        state.queue.clear();
        state.in_flight = None;
    }
}

// Creates one stable redacted live-fanout failure.
const fn fanout_error(reason: &'static str) -> WatchdogError {
    WatchdogError::provider("live fanout", reason)
}
