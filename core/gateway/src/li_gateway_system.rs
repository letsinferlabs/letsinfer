// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use getrandom::fill;
use li_core_interface::{Sha256Digest, UnixMilliseconds};
use sha2::{Digest, Sha256};

use crate::{
    GatewayClock, GatewayError, GatewayHttpError, GatewayHttpRequestIdProvider, GatewayQueueTicket,
    GatewayQueueWaiter,
};

const REQUEST_ID_DOMAIN: &[u8] = b"letsinfer-gateway-request-id-v1\0";
const REQUEST_ID_RANDOM_BYTES: usize = 32;
const DEFAULT_QUEUE_WAIT_MILLISECONDS: u64 = 10;
const MAXIMUM_QUEUE_WAIT_MILLISECONDS: u64 = 1_000;

// Carries one paired wall and monotonic observation from the same native boundary.
#[derive(Clone, Copy)]
struct GatewaySystemTime {
    wall_milliseconds: u64,
    monotonic_milliseconds: u64,
}

// Supplies paired clocks without allowing Gateway policy to read native time directly.
trait GatewaySystemTimeSource: Send + Sync {
    // Returns one bounded wall and monotonic observation.
    fn sample(&self) -> Result<GatewaySystemTime, GatewayError>;
}

// Reads the two fixed POSIX clocks used by the production Gateway.
struct NativeGatewaySystemTimeSource;

impl GatewaySystemTimeSource for NativeGatewaySystemTimeSource {
    // Samples realtime and monotonic clocks through fixed clock identities.
    fn sample(&self) -> Result<GatewaySystemTime, GatewayError> {
        Ok(GatewaySystemTime {
            wall_milliseconds: native_clock_milliseconds(libc::CLOCK_REALTIME)?,
            monotonic_milliseconds: native_clock_milliseconds(libc::CLOCK_MONOTONIC)?,
        })
    }
}

// Rejects clock regressions while supplying exact Unix time to Gateway policy.
pub struct SystemGatewayClock {
    source: Arc<dyn GatewaySystemTimeSource>,
    previous: Mutex<Option<GatewaySystemTime>>,
}

impl SystemGatewayClock {
    // Creates one production clock backed by fixed native wall and monotonic clocks.
    pub fn new() -> Self {
        Self::with_source(Arc::new(NativeGatewaySystemTimeSource))
    }

    // Creates one clock around an injected native-time boundary.
    fn with_source(source: Arc<dyn GatewaySystemTimeSource>) -> Self {
        Self {
            source,
            previous: Mutex::new(None),
        }
    }
}

impl Default for SystemGatewayClock {
    // Creates the ordinary production Gateway clock.
    fn default() -> Self {
        Self::new()
    }
}

impl GatewayClock for SystemGatewayClock {
    // Returns Unix time only when both host clocks remain positive and non-regressing.
    fn now(&self) -> Result<UnixMilliseconds, GatewayError> {
        let sample = self.source.sample()?;
        if sample.wall_milliseconds == 0 || sample.monotonic_milliseconds == 0 {
            return Err(clock_error("native clock value is invalid"));
        }
        let mut previous = self
            .previous
            .lock()
            .map_err(|_| GatewayError::StateUnavailable)?;
        if previous.is_some_and(|previous| {
            sample.wall_milliseconds < previous.wall_milliseconds
                || sample.monotonic_milliseconds < previous.monotonic_milliseconds
        }) {
            return Err(clock_error("native clock regressed"));
        }
        *previous = Some(sample);
        Ok(UnixMilliseconds::new(sample.wall_milliseconds))
    }
}

// Supplies cryptographically secure bytes without exposing the platform random source.
trait GatewayRequestEntropy: Send + Sync {
    // Fills the complete request-identity destination.
    fn fill(&self, destination: &mut [u8]) -> Result<(), GatewayHttpError>;
}

// Reads production request identity material from the operating-system CSPRNG.
struct NativeGatewayRequestEntropy;

impl GatewayRequestEntropy for NativeGatewayRequestEntropy {
    // Fills one destination or returns one redacted internal failure.
    fn fill(&self, destination: &mut [u8]) -> Result<(), GatewayHttpError> {
        fill(destination).map_err(|_| request_identity_error())
    }
}

// Creates domain-separated collision-resistant Gateway request identities.
pub struct SystemGatewayHttpRequestIdProvider {
    entropy: Arc<dyn GatewayRequestEntropy>,
}

impl SystemGatewayHttpRequestIdProvider {
    // Creates one production request-identity provider over the operating-system CSPRNG.
    pub fn new() -> Self {
        Self::with_entropy(Arc::new(NativeGatewayRequestEntropy))
    }

    // Creates one request-identity provider around an injected entropy boundary.
    fn with_entropy(entropy: Arc<dyn GatewayRequestEntropy>) -> Self {
        Self { entropy }
    }
}

impl Default for SystemGatewayHttpRequestIdProvider {
    // Creates the ordinary production request-identity provider.
    fn default() -> Self {
        Self::new()
    }
}

impl GatewayHttpRequestIdProvider for SystemGatewayHttpRequestIdProvider {
    // Hashes one complete random value under the immutable Gateway request domain.
    fn next(&self) -> Result<Sha256Digest, GatewayHttpError> {
        let mut random = [0_u8; REQUEST_ID_RANDOM_BYTES];
        self.entropy.fill(&mut random)?;
        let mut digest = Sha256::new();
        digest.update(REQUEST_ID_DOMAIN);
        digest.update(random);
        Sha256Digest::parse(&format!("{:x}", digest.finalize()))
            .map_err(|_| request_identity_error())
    }
}

// Stores one interruptible bounded wait generation.
struct GatewayQueueWaitState {
    generation: u64,
    interrupted: bool,
}

// Provides short interruptible waits between Gateway-owned queue observations.
pub struct SystemGatewayQueueWaiter {
    maximum_wait: Duration,
    state: Mutex<GatewayQueueWaitState>,
    wake: Condvar,
}

impl SystemGatewayQueueWaiter {
    // Creates one bounded queue waiter from an explicit positive poll duration.
    pub fn new(maximum_wait_milliseconds: u64) -> Result<Self, GatewayError> {
        if maximum_wait_milliseconds == 0
            || maximum_wait_milliseconds > MAXIMUM_QUEUE_WAIT_MILLISECONDS
        {
            return Err(queue_wait_error("wait duration is invalid"));
        }
        Ok(Self {
            maximum_wait: Duration::from_millis(maximum_wait_milliseconds),
            state: Mutex::new(GatewayQueueWaitState {
                generation: 1,
                interrupted: false,
            }),
            wake: Condvar::new(),
        })
    }

    // Wakes current waiters after an external capacity observation changes.
    pub fn wake(&self) -> Result<(), GatewayError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| GatewayError::StateUnavailable)?;
        state.generation = state
            .generation
            .checked_add(1)
            .ok_or_else(|| queue_wait_error("wait generation is exhausted"))?;
        self.wake.notify_all();
        Ok(())
    }

    // Interrupts current and future waits during deterministic process shutdown.
    pub fn interrupt(&self) -> Result<(), GatewayError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| GatewayError::StateUnavailable)?;
        state.interrupted = true;
        self.wake.notify_all();
        Ok(())
    }
}

impl Default for SystemGatewayQueueWaiter {
    // Creates the ordinary short bounded queue waiter.
    fn default() -> Self {
        Self::new(DEFAULT_QUEUE_WAIT_MILLISECONDS).expect("fixed Gateway queue wait bound")
    }
}

impl GatewayQueueWaiter for SystemGatewayQueueWaiter {
    // Waits for one wake generation or timeout while failing closed after interruption.
    fn wait(&self, _ticket: &GatewayQueueTicket) -> Result<(), GatewayError> {
        let state = self
            .state
            .lock()
            .map_err(|_| GatewayError::StateUnavailable)?;
        if state.interrupted {
            return Err(queue_wait_error("wait was interrupted"));
        }
        let generation = state.generation;
        let (state, _) = self
            .wake
            .wait_timeout_while(state, self.maximum_wait, |state| {
                !state.interrupted && state.generation == generation
            })
            .map_err(|_| GatewayError::StateUnavailable)?;
        if state.interrupted {
            return Err(queue_wait_error("wait was interrupted"));
        }
        Ok(())
    }
}

// Reads one positive millisecond value from a fixed POSIX clock.
fn native_clock_milliseconds(clock: libc::clockid_t) -> Result<u64, GatewayError> {
    let mut value = std::mem::MaybeUninit::<libc::timespec>::uninit();
    // SAFETY: clock_gettime initializes value on success for the supplied fixed clock identity.
    if unsafe { libc::clock_gettime(clock, value.as_mut_ptr()) } != 0 {
        return Err(clock_error("native clock is unavailable"));
    }
    // SAFETY: successful clock_gettime initialized the complete timespec value.
    let value = unsafe { value.assume_init() };
    u64::try_from(value.tv_sec)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000))
        .and_then(|milliseconds| {
            u64::try_from(value.tv_nsec)
                .ok()
                .and_then(|nanoseconds| milliseconds.checked_add(nanoseconds / 1_000_000))
        })
        .filter(|milliseconds| *milliseconds > 0)
        .ok_or_else(|| clock_error("native clock value is invalid"))
}

// Creates one redacted native clock failure.
const fn clock_error(reason: &'static str) -> GatewayError {
    GatewayError::provider("clock", reason)
}

// Creates one redacted queue-wait failure.
const fn queue_wait_error(reason: &'static str) -> GatewayError {
    GatewayError::provider("queue_wait", reason)
}

// Creates one stable client-safe request-identity failure.
const fn request_identity_error() -> GatewayHttpError {
    GatewayHttpError::new(500, "internal_error", "request identity is unavailable")
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;

    // Supplies an ordered sequence of paired clock observations.
    struct TimeSource {
        samples: Mutex<VecDeque<GatewaySystemTime>>,
    }

    impl GatewaySystemTimeSource for TimeSource {
        // Returns the next exact clock sample or a bounded provider failure.
        fn sample(&self) -> Result<GatewaySystemTime, GatewayError> {
            self.samples
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| clock_error("mock clock is exhausted"))
        }
    }

    // Returns one deterministic clock over the supplied observations.
    fn clock(samples: &[(u64, u64)]) -> SystemGatewayClock {
        SystemGatewayClock::with_source(Arc::new(TimeSource {
            samples: Mutex::new(
                samples
                    .iter()
                    .map(
                        |(wall_milliseconds, monotonic_milliseconds)| GatewaySystemTime {
                            wall_milliseconds: *wall_milliseconds,
                            monotonic_milliseconds: *monotonic_milliseconds,
                        },
                    )
                    .collect(),
            ),
        }))
    }

    // Supplies fixed bytes or one exact entropy failure.
    struct Entropy {
        byte: u8,
        fails: bool,
    }

    impl GatewayRequestEntropy for Entropy {
        // Fills every byte deterministically unless failure was requested.
        fn fill(&self, destination: &mut [u8]) -> Result<(), GatewayHttpError> {
            if self.fails {
                return Err(request_identity_error());
            }
            destination.fill(self.byte);
            Ok(())
        }
    }

    #[test]
    // Accepts ordered wall and monotonic observations without rewriting Unix identity.
    fn clock_accepts_ordered_observations() {
        let clock = clock(&[(10_000, 2_000), (10_005, 2_004)]);
        assert_eq!(clock.now().unwrap().value(), 10_000);
        assert_eq!(clock.now().unwrap().value(), 10_005);
    }

    #[test]
    // Rejects either wall or monotonic regression and retains the last valid observation.
    fn clock_rejects_time_regression() {
        let wall = clock(&[(10_000, 2_000), (9_999, 2_001)]);
        wall.now().unwrap();
        assert_eq!(
            wall.now().unwrap_err(),
            clock_error("native clock regressed")
        );

        let monotonic = clock(&[(10_000, 2_000), (10_001, 1_999)]);
        monotonic.now().unwrap();
        assert_eq!(
            monotonic.now().unwrap_err(),
            clock_error("native clock regressed")
        );
    }

    #[test]
    // Rejects zero native values instead of fabricating an epoch or monotonic origin.
    fn clock_rejects_invalid_bounds() {
        assert_eq!(
            clock(&[(0, 1)]).now().unwrap_err(),
            clock_error("native clock value is invalid")
        );
        assert_eq!(
            clock(&[(1, 0)]).now().unwrap_err(),
            clock_error("native clock value is invalid")
        );
    }

    #[test]
    // Derives stable domain-separated request identities from complete entropy.
    fn request_identity_is_deterministic_for_injected_entropy() {
        let provider = SystemGatewayHttpRequestIdProvider::with_entropy(Arc::new(Entropy {
            byte: 7,
            fails: false,
        }));
        let first = provider.next().unwrap();
        let second = provider.next().unwrap();
        assert_eq!(first, second);
        assert_eq!(first.as_str().len(), 64);
    }

    #[test]
    // Returns one redacted client-safe failure when operating-system entropy is unavailable.
    fn request_identity_rejects_entropy_failure() {
        let provider = SystemGatewayHttpRequestIdProvider::with_entropy(Arc::new(Entropy {
            byte: 0,
            fails: true,
        }));
        assert_eq!(provider.next().unwrap_err(), request_identity_error());
    }

    #[test]
    // Rejects unbounded queue waits at construction.
    fn queue_waiter_rejects_invalid_bounds() {
        assert!(SystemGatewayQueueWaiter::new(0).is_err());
        assert!(SystemGatewayQueueWaiter::new(MAXIMUM_QUEUE_WAIT_MILLISECONDS + 1).is_err());
    }

    #[test]
    // Wakes a bounded wait through an explicit generation without interrupting future waits.
    fn queue_waiter_accepts_capacity_wake() {
        let waiter = SystemGatewayQueueWaiter::new(1).unwrap();
        waiter.wake().unwrap();
        let ticket = GatewayQueueTicket::new(
            Sha256Digest::parse(&"a".repeat(64)).expect("request identity"),
        );
        assert!(waiter.wait(&ticket).is_ok());
    }

    #[test]
    // Rejects current and future waits after deterministic shutdown interruption.
    fn queue_waiter_rejects_interrupted_waits() {
        let waiter = SystemGatewayQueueWaiter::new(1).unwrap();
        waiter.interrupt().unwrap();
        let ticket = GatewayQueueTicket::new(
            Sha256Digest::parse(&"b".repeat(64)).expect("request identity"),
        );
        assert_eq!(
            waiter.wait(&ticket).unwrap_err(),
            queue_wait_error("wait was interrupted")
        );
    }
}
