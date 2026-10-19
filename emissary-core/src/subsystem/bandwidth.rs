// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

//! Bandwidth metering and limiting.
//!
//! Limits are enforced with token buckets, one per direction and one per direction for transit
//! traffic. Outbound messages that don't fit are queued by `SubsystemManager` and sent once
//! tokens have accumulated, so a limit shapes the traffic instead of dropping it. Inbound
//! messages have already been received by the time they are checked, so inbound traffic is only
//! metered and dropped when the limit is exceeded: transit traffic first, local traffic once it
//! is more than 10% over the limit.
//!
//! Bandwidth usage is also averaged over 5-second and 5-minute windows to compute the router's
//! congestion level which `TransitTunnelManager` uses to reject tunnel build requests and
//! `TransportManager` uses to publish the congestion caps.

use crate::{
    config::BandwidthConfig,
    primitives::Bandwidth,
    runtime::{Instant, Runtime},
    subsystem::Source,
};

use futures::FutureExt;

use alloc::sync::Arc;
use core::{
    sync::atomic::AtomicIsize,
    sync::atomic::{AtomicU8, Ordering},
    task::Context,
    time::Duration,
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::bandwidth";

/// How often token buckets are refilled.
pub const REFILL_INTERVAL: Duration = Duration::from_millis(100);

/// Number of refills per metering slot (one second).
const REFILLS_PER_SLOT: usize = 10usize;

/// Maximum number of refills done at once when the tracker has not been polled for a while.
///
/// Buckets are full and meters are empty after this many refills anyway.
const MAX_CATCH_UP_REFILLS: usize = REFILLS_PER_SLOT * MEDIUM_WINDOW_LEN;

/// Length of the short-term metering window, in seconds.
const SHORT_WINDOW_LEN: usize = 5usize;

/// Length of the medium-term metering window, in seconds.
const MEDIUM_WINDOW_LEN: usize = 300usize;

/// Usage above this fraction of the limit is high congestion.
const HIGH_CONGESTION_THRESHOLD: f64 = 0.9f64;

/// Usage above this fraction of the limit is medium congestion.
const MEDIUM_CONGESTION_THRESHOLD: f64 = 0.7f64;


/// Congestion level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum CongestionLevel {
    /// Low congestion: bandwidth usage is below 70%.
    #[default]
    Low = 0,

    /// Medium congestion: bandwidth usage is between 70% and 90%.
    Medium = 1,

    /// High congestion: bandwidth usage is above 90%.
    High = 2,
}

impl CongestionLevel {
    /// Convert from u8 value.
    fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Low,
            1 => Self::Medium,
            2 => Self::High,
            _ => Self::Low,
        }
    }

    /// Congestion level for `usage` bytes per second against `limit` bytes per second.
    fn for_usage(usage: usize, limit: usize) -> Self {
        if limit == 0 {
            return Self::Low;
        }

        let usage = usage as f64 / limit as f64;

        if usage > HIGH_CONGESTION_THRESHOLD {
            Self::High
        } else if usage > MEDIUM_CONGESTION_THRESHOLD {
            Self::Medium
        } else {
            Self::Low
        }
    }
}

/// Congestion state shared between `BandwidthTracker` and its users.
#[derive(Debug, Default, Clone)]
pub struct Congestion {
    /// Curren congestion.
    congestion: Arc<AtomicU8>,

    /// Bandwidth class of the router.
    bandwidth: Bandwidth,
}

impl Congestion {
    /// Create new `Congestion` with bandwidth class.
    pub fn new(bandwidth: Bandwidth) -> Self {
        Self {
            bandwidth,
            ..Default::default()
        }
    }

    /// Store a new congestion level.
    pub fn store(&self, congestion: CongestionLevel) {
        self.congestion.store(congestion as u8, Ordering::Relaxed);
    }

    /// Load current congestion level.
    pub fn load(&self) -> CongestionLevel {
        CongestionLevel::from_u8(self.congestion.load(Ordering::Relaxed))
    }

    /// Get bandwidth class of the router.
    pub fn bandwidth(&self) -> Bandwidth {
        self.bandwidth
    }
}

/// Verdict for an outbound message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Message can be sent now.
    Send,

    /// Message must wait for the limit to allow it.
    Wait,

    /// Message must be dropped, there is no budget for its kind of traffic.
    Drop,
}

/// Token bucket.
///
/// Tokens are bytes. The bucket is refilled with a fixed amount every [`REFILL_INTERVAL`] and
/// holds at most one second of traffic. Consuming is allowed whenever the bucket isn't in debt
/// and may push it into debt so that a message larger than the burst still gets sent once enough
/// tokens have accumulated.
#[derive(Debug)]
struct TokenBucket {
    /// Maximum number of tokens, one second of traffic.
    burst: i64,

    /// Tokens added per refill.
    refill: i64,

    /// Available tokens, negative if the bucket is in debt.
    tokens: i64,

    /// Is the bucket unlimited.
    unlimited: bool,
}

impl TokenBucket {
    /// Create new `TokenBucket` with `rate` bytes per second.
    ///
    /// A rate of zero means that nothing is allowed through.
    fn new(rate: usize) -> Self {
        Self {
            burst: rate as i64,
            refill: rate.div_ceil(REFILLS_PER_SLOT) as i64,
            tokens: rate as i64,
            unlimited: false,
        }
    }

    /// Create a bucket that allows everything.
    fn unlimited() -> Self {
        Self {
            burst: 0,
            refill: 0,
            tokens: 0,
            unlimited: true,
        }
    }

    /// Does the bucket allow nothing through.
    fn is_closed(&self) -> bool {
        !self.unlimited && self.burst == 0
    }

    /// Does the bucket currently allow a message through.
    ///
    /// A message is allowed as long as there are tokens left, even if it is larger than the
    /// remaining tokens, in which case the bucket goes into debt.
    fn allows(&self) -> bool {
        self.unlimited || self.tokens > 0
    }


    /// Consume `size` tokens.
    fn consume(&mut self, size: usize) {
        if !self.unlimited {
            self.tokens -= size as i64;
        }
    }

    /// Refill the bucket.
    fn refill(&mut self) {
        if !self.unlimited {
            self.tokens = (self.tokens + self.refill).min(self.burst);
        }
    }
}

/// Token bucket shared between threads.
#[derive(Debug, Default)]
struct SharedBucket {
    /// Maximum number of tokens, one second of traffic. Zero means unlimited.
    burst: AtomicIsize,

    /// Tokens added per refill.
    refill: AtomicIsize,

    /// Available tokens, negative if the bucket is in debt.
    tokens: AtomicIsize,
}

/// Inbound bandwidth limiter.
///
/// Shared between [`BandwidthTracker`], which refills it, and the transports, which consume it
/// for every frame or packet they read and stop reading while it has no tokens. NTCP2 slows the
/// remote router down through TCP flow control, SSU2 by letting packets be dropped.
#[derive(Debug, Default, Clone)]
pub struct InboundLimiter {
    /// Shared bucket.
    inner: Arc<SharedBucket>,
}

impl InboundLimiter {
    /// Create new `InboundLimiter` without a limit.
    pub fn unlimited() -> Self {
        Self::default()
    }

    /// Create new `InboundLimiter` with `rate` bytes per second, zero meaning unlimited.
    pub fn new(rate: usize) -> Self {
        let limiter = Self::unlimited();
        limiter.configure(rate);
        limiter
    }

    /// Set the limit to `rate` bytes per second, zero meaning unlimited.
    pub fn configure(&self, rate: usize) {
        self.inner.burst.store(rate as isize, Ordering::Relaxed);
        self.inner.refill.store(rate.div_ceil(REFILLS_PER_SLOT) as isize, Ordering::Relaxed);
        self.inner.tokens.store(rate as isize, Ordering::Relaxed);
    }

    /// Is the limiter unlimited.
    pub fn is_unlimited(&self) -> bool {
        self.inner.burst.load(Ordering::Relaxed) == 0
    }

    /// Does the limiter currently allow reading.
    ///
    /// Reading is allowed as long as there are tokens left, even if what is read is larger
    /// than the remaining tokens, in which case the bucket goes into debt.
    pub fn allows(&self) -> bool {
        self.is_unlimited() || self.inner.tokens.load(Ordering::Relaxed) > 0
    }

    /// Consume `size` tokens.
    pub fn consume(&self, size: usize) {
        if !self.is_unlimited() {
            self.inner.tokens.fetch_sub(size as isize, Ordering::Relaxed);
        }
    }

    /// Refill the bucket.
    pub(crate) fn refill(&self) {
        if self.is_unlimited() {
            return;
        }

        let burst = self.inner.burst.load(Ordering::Relaxed);
        let refill = self.inner.refill.load(Ordering::Relaxed);
        let mut tokens = self.inner.tokens.load(Ordering::Relaxed);

        loop {
            let new = (tokens + refill).min(burst);

            match self.inner.tokens.compare_exchange_weak(
                tokens,
                new,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(current) => tokens = current,
            }
        }
    }

    /// Get available tokens.
    #[cfg(test)]
    pub fn tokens(&self) -> isize {
        self.inner.tokens.load(Ordering::Relaxed)
    }
}

/// Bandwidth usage during one second.
#[derive(Debug, Default, Clone, Copy)]
struct BandwidthSlot {
    /// Total inbound bytes in this slot.
    inbound: usize,

    /// Total outbound bytes in this slot.
    outbound: usize,

    /// Total transit inbound bytes in this slot.
    transit_inbound: usize,

    /// Total transit outbound bytes in this slot.
    transit_outbound: usize,
}

impl BandwidthSlot {
    /// Reset the slot to zero.
    fn reset(&mut self) {
        *self = Self::default();
    }
}

/// Bandwidth meter, a ring buffer of per-second usage.
#[derive(Debug)]
struct BandwidthMeter<const N: usize> {
    /// Ring buffer of bandwidth slots.
    slots: [BandwidthSlot; N],

    /// Current slot index.
    current_slot: usize,

    /// Number of slots that have been filled.
    ///
    /// Used to provide more accurate readings during start-up period.
    filled_slots: usize,
}

impl<const N: usize> BandwidthMeter<N> {
    /// Create a new `BandwidthMeter`.
    fn new() -> Self {
        Self {
            slots: [BandwidthSlot::default(); N],
            current_slot: 0,
            filled_slots: 1,
        }
    }

    /// Record inbound bandwidth.
    fn record_inbound(&mut self, bytes: usize, is_transit: bool) {
        self.slots[self.current_slot].inbound += bytes;

        if is_transit {
            self.slots[self.current_slot].transit_inbound += bytes;
        }
    }

    /// Record outbound bandwidth.
    fn record_outbound(&mut self, bytes: usize, is_transit: bool) {
        self.slots[self.current_slot].outbound += bytes;

        if is_transit {
            self.slots[self.current_slot].transit_outbound += bytes;
        }
    }

    /// Advance to the next time slot.
    fn advance(&mut self) {
        self.current_slot = (self.current_slot + 1) % N;
        self.slots[self.current_slot].reset();

        if self.filled_slots < N {
            self.filled_slots += 1;
        }
    }

    /// Average inbound bytes per second.
    fn average_inbound(&self) -> usize {
        self.slots.iter().take(self.filled_slots).map(|slot| slot.inbound).sum::<usize>()
            / self.filled_slots
    }

    /// Average outbound bytes per second.
    fn average_outbound(&self) -> usize {
        self.slots.iter().take(self.filled_slots).map(|slot| slot.outbound).sum::<usize>()
            / self.filled_slots
    }

    /// Average total bytes per second.
    #[cfg(test)]
    fn average_bandwidth_per_second(&self) -> usize {
        self.average_inbound() + self.average_outbound()
    }
}

/// Bandwidth tracker.
pub struct BandwidthTracker<R: Runtime> {
    /// Current medium-term congestion level.
    congestion_medium: Congestion,

    /// Current short-term congestion level.
    congestion_short: Congestion,

    /// Limiter for all inbound traffic, shared with the transports.
    inbound: InboundLimiter,

    /// Inbound limit, bytes per second.
    inbound_limit: usize,

    /// 5-minute bandwidth meter.
    meter_medium: BandwidthMeter<MEDIUM_WINDOW_LEN>,

    /// 5-second bandwidth meter.
    meter_short: BandwidthMeter<SHORT_WINDOW_LEN>,

    /// Token bucket for all outbound traffic.
    outbound: TokenBucket,

    /// Outbound limit, bytes per second.
    outbound_limit: usize,

    /// Elapsed time not yet accounted for by a refill.
    carry: Duration,

    /// When the buckets were last refilled.
    last_refill: R::Instant,

    /// Number of refills since the meters were last advanced.
    refills: usize,

    /// Timer for refilling the buckets.
    timer: R::Timer,

    /// Token bucket for inbound transit traffic.
    transit_inbound: TokenBucket,

    /// Token bucket for outbound transit traffic.
    transit_outbound: TokenBucket,
}

impl<R: Runtime> BandwidthTracker<R> {
    /// Create new `BandwidthTracker`.
    ///
    /// Returns three objects:
    /// * `BandwidthTracker` given to `SubsystemManager`
    /// * `Congestion` for short-term congestion detection, given to `TransitTunnelManager`
    /// * `Congestion` for medium-term congestion detection, given to `TransportManager`
    ///
    /// `TransitTunnelManager` uses the `Congestion` object to detect congestion. If congestion is
    /// high, all tunnnel build requests are rejected and if congestion is medium, the inbound
    /// tunnel build request is rejected with a 50/50 chance.
    ///
    /// `TransportManager` uses the `Congestion` object to publish correct congestion caps and
    /// bandwidth class.
    pub fn new(config: BandwidthConfig) -> (Self, Congestion, Congestion) {
        let transit_rate =
            |limit: usize| (limit as f64 * config.share_ratio.clamp(0.0, 1.0)) as usize;
        let bucket = |limit: usize| {
            if limit == 0 {
                TokenBucket::unlimited()
            } else {
                TokenBucket::new(limit)
            }
        };
        let transit_bucket = |limit: usize| {
            if limit == 0 {
                TokenBucket::unlimited()
            } else {
                TokenBucket::new(transit_rate(limit))
            }
        };

        // advertised bandwidth class is what transit traffic can get in the slower direction
        let class = match (config.inbound, config.outbound) {
            (0, 0) => Bandwidth::X,
            (0, limit) | (limit, 0) => Bandwidth::from(transit_rate(limit)),
            (inbound, outbound) => Bandwidth::from(transit_rate(inbound.min(outbound))),
        };
        let congestion_short = Congestion::new(class);
        let congestion_medium = Congestion::new(class);

        (
            Self {
                congestion_medium: congestion_medium.clone(),
                congestion_short: congestion_short.clone(),
                inbound: InboundLimiter::new(config.inbound),
                inbound_limit: config.inbound,
                meter_medium: BandwidthMeter::new(),
                meter_short: BandwidthMeter::new(),
                outbound: bucket(config.outbound),
                outbound_limit: config.outbound,
                carry: Duration::ZERO,
                last_refill: R::now(),
                refills: 0usize,
                timer: R::timer(REFILL_INTERVAL),
                transit_inbound: transit_bucket(config.inbound),
                transit_outbound: transit_bucket(config.outbound),
            },
            congestion_short,
            congestion_medium,
        )
    }

    /// Get a copy of the inbound limiter.
    #[cfg(test)]
    pub fn inbound_limiter(&self) -> InboundLimiter {
        self.inbound.clone()
    }

    /// Use `limiter`, shared with the transports, as the inbound limiter.
    ///
    /// The limiter is configured with the inbound limit of this tracker.
    pub fn set_inbound_limiter(&mut self, limiter: InboundLimiter) {
        limiter.configure(self.inbound_limit);
        self.inbound = limiter;
    }

    /// Get verdict for an outbound message of `size` bytes from `source`.
    ///
    /// If the message can be sent, its bytes are consumed from the buckets and recorded.
    pub fn outbound_verdict(&mut self, size: usize, source: Source) -> Verdict {
        if source.is_transit() {
            if self.transit_outbound.is_closed() {
                return Verdict::Drop;
            }

            if !self.transit_outbound.allows() {
                return Verdict::Wait;
            }
        }

        if !self.outbound.allows() {
            return Verdict::Wait;
        }

        self.outbound.consume(size);
        if source.is_transit() {
            self.transit_outbound.consume(size);
        }
        self.meter_short.record_outbound(size, source.is_transit());
        self.meter_medium.record_outbound(size, source.is_transit());

        Verdict::Send
    }

    /// Record an inbound message of `size` bytes from `source`.
    ///
    /// Returns `true` if the message must be dropped because the transit budget has been
    /// exceeded. The inbound limit itself is enforced by the transports, which stop reading
    /// while the shared [`InboundLimiter`] has no tokens, so local traffic is never dropped
    /// here.
    pub fn inbound_exceeded(&mut self, size: usize, source: Source) -> bool {
        if source.is_transit()
            && (self.transit_inbound.is_closed()
                || !self.transit_inbound.allows()
                || !self.inbound.allows())
        {
            return true;
        }

        if source.is_transit() {
            self.transit_inbound.consume(size);
        }
        self.meter_short.record_inbound(size, source.is_transit());
        self.meter_medium.record_inbound(size, source.is_transit());

        false
    }

    /// Refill the buckets and, once a second, advance the meters and update congestion.
    fn refill(&mut self) {
        self.inbound.refill();
        self.outbound.refill();
        self.transit_inbound.refill();
        self.transit_outbound.refill();
        self.refills += 1;

        if self.refills >= REFILLS_PER_SLOT {
            self.refills = 0;
            self.calculate_congestion();
            self.meter_short.advance();
            self.meter_medium.advance();
        }
    }

    /// Calculate congestion from the meters and update congestion states.
    fn calculate_congestion(&mut self) {
        let level = |inbound: usize, outbound: usize| {
            CongestionLevel::for_usage(inbound, self.inbound_limit)
                .max(CongestionLevel::for_usage(outbound, self.outbound_limit))
        };

        self.congestion_short.store(level(
            self.meter_short.average_inbound(),
            self.meter_short.average_outbound(),
        ));
        self.congestion_medium.store(level(
            self.meter_medium.average_inbound(),
            self.meter_medium.average_outbound(),
        ));
    }

    /// Poll the refill timer.
    ///
    /// Returns `true` if the buckets were refilled, in which case queued outbound messages may
    /// now be sendable.
    pub fn poll_refill(&mut self, cx: &mut Context<'_>) -> bool {
        if self.timer.poll_unpin(cx).is_pending() {
            return false;
        }

        self.catch_up(self.last_refill.elapsed());
        self.last_refill = R::now();
        self.timer = R::timer(REFILL_INTERVAL);

        tracing::trace!(
            target: LOG_TARGET,
            inbound = ?self.inbound.inner.tokens,
            outbound = ?self.outbound.tokens,
            "buckets refilled",
        );

        true
    }

    /// Refill the buckets once per `REFILL_INTERVAL` of `elapsed` time.
    ///
    /// The timer has fired so at least one refill is done. Time left over is carried to the next
    /// call so a late poll doesn't lose bandwidth.
    fn catch_up(&mut self, elapsed: Duration) {
        let total = self.carry.saturating_add(elapsed);
        let (refills, carry) = match (total.as_millis() / REFILL_INTERVAL.as_millis()) as usize {
            0 => (1usize, Duration::ZERO),
            refills if refills > MAX_CATCH_UP_REFILLS => (MAX_CATCH_UP_REFILLS, Duration::ZERO),
            refills => (
                refills,
                Duration::from_millis((total.as_millis() % REFILL_INTERVAL.as_millis()) as u64),
            ),
        };

        for _ in 0..refills {
            self.refill();
        }
        self.carry = carry;
    }
}

impl PartialOrd for CongestionLevel {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CongestionLevel {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        (*self as u8).cmp(&(*other as u8))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::mock::MockRuntime;

    fn config(inbound: usize, outbound: usize, share_ratio: f64) -> BandwidthConfig {
        BandwidthConfig {
            inbound,
            outbound,
            share_ratio,
        }
    }

    #[test]
    fn token_bucket_refills_and_allows_debt() {
        let mut bucket = TokenBucket::new(1000);
        assert!(bucket.allows());

        // a message larger than the burst is allowed and leaves the bucket in debt
        bucket.consume(1500);
        assert!(!bucket.allows());
        assert_eq!(bucket.tokens, -500);

        // five refills of 100 bytes bring the bucket back to zero, the sixth makes it positive
        for _ in 0..5 {
            bucket.refill();
            assert!(!bucket.allows());
        }
        bucket.refill();
        assert!(bucket.allows());

        // tokens never exceed the burst
        for _ in 0..100 {
            bucket.refill();
        }
        assert_eq!(bucket.tokens, 1000);

        // closed and unlimited buckets
        assert!(TokenBucket::new(0).is_closed());
        assert!(!TokenBucket::new(0).allows());
        assert!(TokenBucket::unlimited().allows());
        let mut unlimited = TokenBucket::unlimited();
        unlimited.consume(usize::MAX / 2);
        assert!(unlimited.allows());
    }

    #[tokio::test]
    async fn bandwidth_class_from_slower_direction() {
        let (tracker, congestion, _) =
            BandwidthTracker::<MockRuntime>::new(config(100_000, 2_000_000, 0.5));
        assert_eq!(congestion.bandwidth(), Bandwidth::from(50_000));
        assert_eq!(tracker.transit_outbound.burst, 1_000_000);
        assert_eq!(tracker.transit_inbound.burst, 50_000);

        let (_, congestion, _) = BandwidthTracker::<MockRuntime>::new(config(0, 0, 0.9));
        assert_eq!(congestion.bandwidth(), Bandwidth::X);
    }

    #[tokio::test]
    async fn outbound_transit_waits_for_its_share() {
        let (mut tracker, ..) = BandwidthTracker::<MockRuntime>::new(config(1000, 1000, 0.5));

        // transit may use 500 bytes per second
        assert_eq!(tracker.outbound_verdict(400, Source::Transit), Verdict::Send);
        assert_eq!(tracker.outbound_verdict(400, Source::Transit), Verdict::Send);
        assert_eq!(tracker.outbound_verdict(100, Source::Transit), Verdict::Wait);

        // local traffic has the rest of the total budget
        assert_eq!(tracker.outbound_verdict(200, Source::Client), Verdict::Send);
        assert_eq!(tracker.outbound_verdict(200, Source::Client), Verdict::Wait);

        // after a second everything is allowed again
        for _ in 0..REFILLS_PER_SLOT {
            tracker.refill();
        }
        assert_eq!(tracker.outbound_verdict(100, Source::Transit), Verdict::Send);
        assert_eq!(tracker.outbound_verdict(100, Source::Client), Verdict::Send);
    }

    #[tokio::test]
    async fn outbound_transit_dropped_without_share() {
        let (mut tracker, ..) = BandwidthTracker::<MockRuntime>::new(config(1000, 1000, 0.0));

        assert_eq!(tracker.outbound_verdict(100, Source::Transit), Verdict::Drop);
        assert_eq!(tracker.outbound_verdict(100, Source::Client), Verdict::Send);
    }

    #[tokio::test]
    async fn unlimited_outbound_always_sends() {
        let (mut tracker, ..) = BandwidthTracker::<MockRuntime>::new(config(1000, 0, 0.5));

        for _ in 0..100 {
            assert_eq!(tracker.outbound_verdict(10_000, Source::Client), Verdict::Send);
            assert_eq!(tracker.outbound_verdict(10_000, Source::Transit), Verdict::Send);
        }
    }

    #[tokio::test]
    async fn inbound_transit_dropped_first() {
        let (mut tracker, ..) = BandwidthTracker::<MockRuntime>::new(config(1000, 1000, 0.5));
        let limiter = tracker.inbound_limiter();

        // transit budget is 500 bytes, the bucket may go into debt once
        assert!(!tracker.inbound_exceeded(400, Source::Transit));
        assert!(!tracker.inbound_exceeded(400, Source::Transit));
        assert!(tracker.inbound_exceeded(100, Source::Transit));

        // local traffic is never dropped here, the transports throttle it
        limiter.consume(2000);
        assert!(!limiter.allows());
        assert!(!tracker.inbound_exceeded(1000, Source::Client));

        // transit is dropped while the shared inbound bucket is exhausted, even if the transit
        // bucket has recovered
        for _ in 0..REFILLS_PER_SLOT {
            tracker.refill();
        }
        assert_eq!(limiter.tokens(), 0);
        assert!(tracker.inbound_exceeded(1, Source::Transit));

        tracker.refill();
        assert_eq!(limiter.tokens(), 100);
        assert!(!tracker.inbound_exceeded(1, Source::Transit));
    }

    #[tokio::test]
    async fn inbound_limiter_shared_with_transports() {
        let (mut tracker, ..) = BandwidthTracker::<MockRuntime>::new(config(1000, 0, 0.5));
        let limiter = tracker.inbound_limiter();
        assert!(!limiter.is_unlimited());
        assert_eq!(limiter.tokens(), 1000);

        // consumption through a copy is visible to the tracker
        limiter.clone().consume(1500);
        assert_eq!(limiter.tokens(), -500);
        assert!(!limiter.allows());
        assert!(tracker.inbound_exceeded(1, Source::Transit));

        // refills by the tracker are visible to the transports, tokens never exceed the burst
        for _ in 0..6 {
            tracker.refill();
        }
        assert_eq!(limiter.tokens(), 100);
        assert!(limiter.allows());
        for _ in 0..100 {
            tracker.refill();
        }
        assert_eq!(limiter.tokens(), 1000);

        // a limiter created elsewhere takes the tracker's limit when installed
        let shared = InboundLimiter::unlimited();
        assert!(shared.is_unlimited());
        shared.consume(usize::MAX / 4);
        assert!(shared.allows());

        tracker.set_inbound_limiter(shared.clone());
        assert!(!shared.is_unlimited());
        assert_eq!(shared.tokens(), 1000);
        shared.consume(1000);
        assert!(!shared.allows());
        assert!(tracker.inbound_exceeded(1, Source::Transit));
        tracker.refill();
        assert!(shared.allows());

        // an unlimited configuration never throttles
        let (tracker, ..) = BandwidthTracker::<MockRuntime>::new(config(0, 0, 0.5));
        let limiter = tracker.inbound_limiter();
        assert!(limiter.is_unlimited());
        limiter.consume(usize::MAX / 4);
        assert!(limiter.allows());
    }

    #[tokio::test]
    async fn bandwidth_recorded_in_meters() {
        let (mut tracker, ..) = BandwidthTracker::<MockRuntime>::new(config(10000, 10000, 0.8));

        assert!(!tracker.inbound_exceeded(100, Source::Client));
        assert_eq!(tracker.outbound_verdict(1000, Source::Transit), Verdict::Send);

        assert_eq!(tracker.meter_short.average_bandwidth_per_second(), 1100);
        assert_eq!(tracker.meter_medium.average_bandwidth_per_second(), 1100);
        assert_eq!(tracker.meter_short.slots[0].transit_outbound, 1000);
        assert_eq!(tracker.meter_short.slots[0].transit_inbound, 0);
    }

    #[tokio::test]
    async fn congestion_levels() {
        let (mut tracker, congestion, _) =
            BandwidthTracker::<MockRuntime>::new(config(1000, 1000, 0.8));

        assert!(!tracker.inbound_exceeded(600, Source::Client));
        tracker.calculate_congestion();
        assert_eq!(congestion.load(), CongestionLevel::Low);

        assert!(!tracker.inbound_exceeded(200, Source::Client));
        tracker.calculate_congestion();
        assert_eq!(congestion.load(), CongestionLevel::Medium);

        // congestion follows the busier direction
        assert_eq!(tracker.outbound_verdict(950, Source::Client), Verdict::Send);
        tracker.calculate_congestion();
        assert_eq!(congestion.load(), CongestionLevel::High);

        // unlimited directions never count as congested
        let (mut tracker, congestion, _) = BandwidthTracker::<MockRuntime>::new(config(0, 0, 0.8));
        assert_eq!(tracker.outbound_verdict(1_000_000, Source::Client), Verdict::Send);
        tracker.calculate_congestion();
        assert_eq!(congestion.load(), CongestionLevel::Low);
    }

    #[test]
    fn meter_average_calculation() {
        let mut meter = BandwidthMeter::<5>::new();
        meter.record_inbound(100, false);
        meter.advance();
        meter.record_inbound(200, false);

        assert_eq!(meter.average_bandwidth_per_second(), 150);
    }

    #[tokio::test(start_paused = true)]
    async fn refill_timer_advances_meters() {
        let (mut tracker, ..) = BandwidthTracker::<MockRuntime>::new(config(1000, 1000, 0.5));
        assert_eq!(tracker.outbound_verdict(1000, Source::Client), Verdict::Send);
        assert_eq!(tracker.outbound_verdict(1, Source::Client), Verdict::Wait);

        // nothing refilled yet
        assert!(!futures::future::poll_fn(|cx| core::task::Poll::Ready(tracker.poll_refill(cx)))
            .await);

        // one refill interval later the bucket has 100 bytes again
        tokio::time::sleep(REFILL_INTERVAL + Duration::from_millis(1)).await;
        assert!(futures::future::poll_fn(|cx| core::task::Poll::Ready(tracker.poll_refill(cx)))
            .await);
        assert_eq!(tracker.outbound.tokens, 100);
        assert_eq!(tracker.outbound_verdict(100, Source::Client), Verdict::Send);
        assert_eq!(tracker.outbound_verdict(1, Source::Client), Verdict::Wait);
        assert_eq!(tracker.refills, 1);

        // ten refills later the meters have advanced
        for _ in 0..REFILLS_PER_SLOT {
            tokio::time::sleep(REFILL_INTERVAL).await;
            assert!(futures::future::poll_fn(|cx| core::task::Poll::Ready(
                tracker.poll_refill(cx)
            ))
            .await);
        }
        assert_eq!(tracker.refills, 1);
        assert_eq!(tracker.meter_short.filled_slots, 2);
    }

    #[tokio::test]
    async fn late_poll_catches_up() {
        let (mut tracker, ..) = BandwidthTracker::<MockRuntime>::new(config(1000, 1000, 0.5));
        assert_eq!(tracker.outbound_verdict(1000, Source::Client), Verdict::Send);
        assert_eq!(tracker.outbound.tokens, 0);

        // the timer fired early or mock time stood still: still one refill
        tracker.catch_up(Duration::ZERO);
        assert_eq!(tracker.outbound.tokens, 100);
        assert_eq!(tracker.carry, Duration::ZERO);

        // 250 ms late: two refills, 50 ms carried over
        tracker.catch_up(Duration::from_millis(250));
        assert_eq!(tracker.outbound.tokens, 300);
        assert_eq!(tracker.carry, Duration::from_millis(50));

        // the carry completes the next interval
        tracker.catch_up(Duration::from_millis(50));
        assert_eq!(tracker.outbound.tokens, 400);
        assert_eq!(tracker.carry, Duration::ZERO);

        // a long pause refills at most the bucket, the meters have been advanced and reset
        tracker.catch_up(Duration::from_secs(3600));
        assert_eq!(tracker.outbound.tokens, 1000);
        assert_eq!(tracker.carry, Duration::ZERO);
        assert_eq!(tracker.meter_short.average_outbound(), 0);
    }
}
