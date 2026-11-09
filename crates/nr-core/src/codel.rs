//! CoDel: keep the *standing* queue short, not just the average.
//!
//! A shaper with a byte budget and a 250 ms ceiling can still hold a queue that
//! is always 200 ms deep: nothing is dropped, every packet arrives, and every
//! conversation feels slow. That is bufferbloat, and it is invisible to a
//! drop-based metric. CoDel (RFC 8289, Nichols & Jacobson) is the standard
//! answer: watch the *minimum* sojourn time over a window, and if that minimum
//! stays above a target for a whole interval, the queue is standing rather than
//! bursting — start dropping, and drop more often the longer it persists.
//!
//! The control law, as implemented here:
//!
//! * `sojourn < target` -> the queue is fine; clear the "above target since"
//!   timestamp and the drop counter.
//! * `sojourn >= target` for the first time -> remember when, but do nothing.
//!   A burst is allowed to drain on its own.
//! * Still above target one whole interval later -> the delay is standing:
//!   drop this packet and schedule the next drop `interval / sqrt(count)`
//!   later, so a persistent queue is attacked harder as it persists.
//!
//! Two details that make it work on real traffic and are easy to get wrong:
//!
//! 1. **It drops on the way out, not the way in.** A packet that has waited
//!    3 ms in a 1 ms target queue says nothing; the question is whether the
//!    queue is still deep now.
//! 2. **Disabling is the default.** `target == 0` means "never drop", so every
//!    existing configuration keeps exactly the behaviour it had before CoDel
//!    existed, and the cost is one comparison on the drain path.
//!
//! What this does *not* do: it does not detect congestion on a link we do not
//! own. It bounds the delay *we* add by holding packets, which is the only
//! delay this program is responsible for.

/// Standing-queue target and observation interval, in nanoseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Codel {
    target_ns: u64,
    interval_ns: u64,
    /// When the sojourn time was first seen above the target, if it still is.
    first_above_ns: Option<u64>,
    /// Earliest instant the next drop may happen while in the drop state.
    next_drop_ns: u64,
    /// Drops in the current above-target episode, for `interval / sqrt(count)`.
    episode_drops: u32,
    /// Drops since start-up, for the snapshot.
    drops: u64,
}

impl Default for Codel {
    fn default() -> Self {
        Self::disabled()
    }
}

impl Codel {
    /// CoDel that never drops anything (the default).
    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            target_ns: 0,
            interval_ns: 0,
            first_above_ns: None,
            next_drop_ns: 0,
            episode_drops: 0,
            drops: 0,
        }
    }

    /// CoDel with `target_ns` and `interval_ns`; zero either one to disable.
    #[must_use]
    pub const fn new(target_ns: u64, interval_ns: u64) -> Self {
        Self {
            target_ns,
            interval_ns,
            first_above_ns: None,
            next_drop_ns: 0,
            episode_drops: 0,
            drops: 0,
        }
    }

    /// Is this instance armed?
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.target_ns > 0 && self.interval_ns > 0
    }

    /// The target sojourn time, ns (0 when disabled).
    #[must_use]
    pub const fn target_ns(&self) -> u64 {
        self.target_ns
    }

    /// Drops this instance has performed since start-up.
    #[must_use]
    pub const fn drops(&self) -> u64 {
        self.drops
    }

    /// Is the queue currently in the dropping state?
    #[must_use]
    pub const fn dropping(&self) -> bool {
        self.first_above_ns.is_some()
    }

    /// Decide the fate of one packet that has waited `sojourn_ns`.
    ///
    /// `true` means "drop it": the queue has been standing above the target for
    /// at least one interval, and this packet is due to be sacrificed so the
    /// others are not late.
    pub fn should_drop(&mut self, now_ns: u64, sojourn_ns: u64) -> bool {
        if !self.is_enabled() {
            return false;
        }
        if sojourn_ns < self.target_ns {
            // A packet that did not wait too long means the queue drained; the
            // episode ends and the next one starts from a clean slate.
            self.first_above_ns = None;
            self.episode_drops = 0;
            self.next_drop_ns = 0;
            return false;
        }
        let first = match self.first_above_ns {
            Some(t) => t,
            None => {
                // Above the target for the first time: a burst may still drain
                // on its own, so wait a whole interval before acting.
                self.first_above_ns = Some(now_ns);
                return false;
            }
        };
        if now_ns.saturating_sub(first) < self.interval_ns {
            return false;
        }
        if now_ns < self.next_drop_ns {
            return false;
        }

        self.drops += 1;
        self.episode_drops = self.episode_drops.saturating_add(1);
        // Drop one packet per interval at first, then more often: the spacing
        // shrinks as 1/sqrt(count) while the queue stays above target.
        let spacing = self.interval_ns / u64::from(isqrt(self.episode_drops));
        self.next_drop_ns = now_ns.saturating_add(spacing.max(1));
        true
    }
}

/// Integer square root, rounded down.
///
/// Hand-rolled because the alternative is a `f64` conversion on the packet
/// path, and `f64` has no business deciding whether a packet is dropped.
#[must_use]
pub fn isqrt(n: u32) -> u32 {
    if n < 2 {
        return n;
    }
    let mut x = n;
    let mut y = x.div_ceil(2);
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: u64 = 1_000_000;
    const TARGET: u64 = 5 * MS;
    const INTERVAL: u64 = 100 * MS;

    #[test]
    fn integer_sqrt_is_exact_on_squares_and_close_between_them() {
        assert_eq!(isqrt(0), 0);
        assert_eq!(isqrt(1), 1);
        assert_eq!(isqrt(4), 2);
        assert_eq!(isqrt(9), 3);
        assert_eq!(isqrt(10), 3);
        assert_eq!(isqrt(1_000_000), 1_000);
        assert_eq!(isqrt(u32::MAX), 65_535);
    }

    #[test]
    fn a_disabled_instance_never_drops() {
        let mut c = Codel::disabled();
        assert!(!c.is_enabled());
        for now in [0, INTERVAL, 10 * INTERVAL] {
            assert!(!c.should_drop(now, 10 * MS));
        }
        assert_eq!(c.drops(), 0);
    }

    #[test]
    fn a_burst_below_target_is_never_dropped() {
        let mut c = Codel::new(TARGET, INTERVAL);
        // 200 packets that each waited less than the target: exactly the case
        // CoDel exists to *not* punish.
        for i in 0..200u64 {
            assert!(!c.should_drop(i * MS, 4 * MS), "packet {i}");
        }
        assert_eq!(c.drops(), 0);
        assert!(!c.dropping());
    }

    #[test]
    fn a_standing_queue_starts_dropping_after_one_interval() {
        let mut c = Codel::new(TARGET, INTERVAL);
        // Above target at t=0: remembered, not dropped.
        assert!(!c.should_drop(0, 20 * MS));
        assert!(c.dropping());
        // Half an interval later: still patient.
        assert!(!c.should_drop(50 * MS, 20 * MS));
        // A full interval: the delay is standing, so this packet goes.
        assert!(c.should_drop(INTERVAL, 20 * MS));
        assert_eq!(c.drops(), 1);
        // And not the next one immediately: drops are spaced by an interval.
        assert!(!c.should_drop(INTERVAL + MS, 20 * MS));
    }

    #[test]
    fn drops_escalate_while_the_queue_stays_deep() {
        let mut c = Codel::new(TARGET, INTERVAL);
        assert!(!c.should_drop(0, 20 * MS));
        let mut now = INTERVAL;
        let mut dropped = 0;
        // Offer a packet every millisecond for four intervals while the queue
        // never drains: the spacing must tighten (interval/sqrt(count)).
        for _ in 0..400 {
            if c.should_drop(now, 20 * MS) {
                dropped += 1;
            }
            now += MS;
        }
        assert!(
            dropped >= 4,
            "a standing queue must be dropped from repeatedly, got {dropped}"
        );
        assert_eq!(c.drops(), dropped);
    }

    #[test]
    fn a_queue_that_drains_resets_the_episode() {
        let mut c = Codel::new(TARGET, INTERVAL);
        assert!(!c.should_drop(0, 20 * MS));
        assert!(c.should_drop(INTERVAL, 20 * MS));
        assert_eq!(c.drops(), 1);

        // One packet that did not wait: the queue is no longer standing.
        assert!(!c.should_drop(INTERVAL + MS, MS));
        assert!(!c.dropping());

        // A new episode has to start from scratch: patient for an interval.
        assert!(!c.should_drop(200 * MS, 20 * MS));
        assert!(!c.should_drop(250 * MS, 20 * MS));
        assert!(c.should_drop(300 * MS, 20 * MS));
        assert_eq!(c.drops(), 2);
    }
}
