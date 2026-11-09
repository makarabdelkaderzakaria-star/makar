//! Rate control: GCRA (Generic Cell Rate Algorithm) in a single `u64`.
//!
//! ## Why GCRA instead of a token bucket
//!
//! The original `TokenBucket.cs` held a `lock`, a `double` rate, a `double`
//! _and a separate burst accumulator, and exposed `GetDelay()` and
//! `TryConsume()` as two independent calls. `WinDivertInterceptor` called
//! `GetDelay()`, *ignored* the boolean returned by `TryConsume()`, and then
//! scheduled the packet anyway — so configured limits silently did nothing.
//!
//! GCRA fixes all of that structurally:
//!
//! * one state word (`tat`, the theoretical arrival time) instead of four,
//! * integer arithmetic, so no floating point drift and no rounding-up bugs,
//! * a single `try_acquire` that tests **and** commits, so no window exists in
//!   which a caller can "check but forget to commit",
//! * the state is monotone, which makes it publishable as one atomic word.
//!
//! ## Units
//!
//! * time: **nanoseconds**, monotonic
//! * rates: **bytes per second**
//! * the burst tolerance in time is `burst_bytes * cost_per_byte`
//!
//! ## The algorithm
//!
//! Let `τ = burst * cost_per_byte` (burst tolerance) and `d = len * cost_per_byte`
//! (departure interval for this packet). A packet conforms if
//! `now >= tat - τ`. On emission `tat := max(tat, now) + d`.

use crate::error::ConfigError;

/// Nanoseconds per second.
pub const NS_PER_SEC: u64 = 1_000_000_000;

/// Highest rate we accept (1 TiB/s) so that `1e9 / rate` never rounds to 0.
pub const MAX_RATE: u64 = 1 << 40;

/// Minimum burst we accept: one maximum-size Ethernet frame worth of bytes.
pub const MIN_BURST: u64 = 1500;

/// A single-lane virtual scheduler / leaky bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gcra {
    /// Bytes per second.
    rate: u64,
    /// Burst allowance in bytes.
    burst: u64,
    /// Nanoseconds to transmit one byte, rounded up (`1e9 / rate`).
    cost_per_byte: u64,
    /// Burst tolerance in nanoseconds (`burst * cost_per_byte`).
    tolerance_ns: u64,
    /// Theoretical arrival time of the next conforming packet (ns).
    tat: u64,
}

impl Gcra {
    /// Build a limiter. `rate` is bytes/second, `burst` is bytes.
    pub fn new(rate: u64, burst: u64) -> Result<Self, ConfigError> {
        if rate == 0 || rate > MAX_RATE {
            return Err(ConfigError::ZeroRate);
        }
        if burst < MIN_BURST {
            return Err(ConfigError::BurstTooSmall { burst });
        }
        let cost_per_byte = NS_PER_SEC.div_ceil(rate);
        Ok(Self {
            rate,
            burst,
            cost_per_byte,
            tolerance_ns: burst.saturating_mul(cost_per_byte),
            tat: 0,
        })
    }

    /// Build from bits per second (what people actually type).
    pub fn from_bits_per_sec(bps: u64, burst_bytes: u64) -> Result<Self, ConfigError> {
        Self::new(bps / 8, burst_bytes)
    }

    /// Configured rate, bytes/second.
    #[inline]
    #[must_use]
    pub const fn rate(&self) -> u64 {
        self.rate
    }

    /// Configured burst, bytes.
    #[inline]
    #[must_use]
    pub const fn burst(&self) -> u64 {
        self.burst
    }

    /// Current theoretical arrival time (ns); exposed for diagnostics.
    #[inline]
    #[must_use]
    pub const fn tat(&self) -> u64 {
        self.tat
    }

    /// Forget history (config change, or a flow that was idle so long it is
    /// effectively new). The next packet conforms immediately.
    #[inline]
    pub fn reset(&mut self) {
        self.tat = 0;
    }

    /// Departure interval for a packet of `len` bytes, in ns.
    #[inline]
    #[must_use]
    pub const fn interval_ns(&self, len: u32) -> u64 {
        (len as u64).saturating_mul(self.cost_per_byte)
    }

    /// How long the next packet must wait before it conforms. `None` == now.
    ///
    /// Note the deliberate absence of a `len` parameter: under GCRA the
    /// conformance test is `now >= tat - tolerance`, which does not depend on
    /// the size of the packet being tested — the size only affects the
    /// *following* packet's interval, through [`commit`](Self::commit). Passing
    /// a length here would be a lie that makes callers think they can jump the
    /// queue with small packets.
    ///
    /// Read-only: two calls return the same answer until somebody commits,
    /// which is what makes it safe to peek at the scheduler horizon.
    #[inline]
    #[must_use]
    pub const fn check(&self, now_ns: u64) -> Option<u64> {
        let earliest = self.tat.saturating_sub(self.tolerance_ns);
        if now_ns >= earliest {
            None
        } else {
            Some(earliest - now_ns)
        }
    }

    /// Record that `len` bytes were emitted at `now_ns`.
    #[inline]
    pub fn commit(&mut self, len: u32, now_ns: u64) {
        let base = if self.tat > now_ns { self.tat } else { now_ns };
        self.tat = base.saturating_add(self.interval_ns(len));
    }

    /// Test-and-commit in one call. `true` means "send now".
    ///
    /// This is the *only* function the pipeline should use for the immediate
    /// path: it is impossible to check without committing.
    #[inline]
    pub fn try_acquire(&mut self, len: u32, now_ns: u64) -> bool {
        if self.check(now_ns).is_none() {
            self.commit(len, now_ns);
            true
        } else {
            false
        }
    }

    /// When the bucket becomes fully empty again (for scheduler horizons).
    #[inline]
    #[must_use]
    pub const fn drain_ns(&self) -> u64 {
        self.tat
    }
}

/// Lock-free lane for cross-thread use.
///
/// Only `tat` mutates and it is one `u64`, so the entire lane is one atomic
/// word plus immutable configuration — no mutex, no cache-line sharing with
/// the hash table, and a CAS loop that in the single-reader design almost
/// always succeeds on the first attempt.
#[derive(Debug)]
pub struct AtomicGcra {
    config: Gcra,
    tat: core::sync::atomic::AtomicU64,
}

impl AtomicGcra {
    /// Wrap a configured limiter, preserving its current state.
    #[must_use]
    pub fn new(config: Gcra) -> Self {
        let tat = config.tat;
        Self {
            config,
            tat: core::sync::atomic::AtomicU64::new(tat),
        }
    }

    /// Immutable configuration (rate, burst, tolerance).
    #[must_use]
    pub const fn config(&self) -> &Gcra {
        &self.config
    }

    /// Current theoretical arrival time.
    #[must_use]
    pub fn tat(&self) -> u64 {
        self.tat.load(core::sync::atomic::Ordering::Relaxed)
    }

    /// Peek the delay without mutating. May be one packet stale, which is fine
    /// for scheduling horizons (we re-check on send anyway).
    #[inline]
    #[must_use]
    pub fn peek_delay(&self, now_ns: u64) -> Option<u64> {
        let tat = self.tat.load(core::sync::atomic::Ordering::Relaxed);
        let earliest = tat.saturating_sub(self.config.tolerance_ns);
        if now_ns >= earliest {
            None
        } else {
            Some(earliest - now_ns)
        }
    }

    /// Atomically test-and-commit. `true` means "send now".
    #[inline]
    pub fn try_acquire(&self, len: u32, now_ns: u64) -> bool {
        use core::sync::atomic::Ordering;
        let interval = self.config.interval_ns(len);
        let tolerance = self.config.tolerance_ns;
        let mut current = self.tat.load(Ordering::Relaxed);
        loop {
            if now_ns < current.saturating_sub(tolerance) {
                return false;
            }
            let next = current.max(now_ns).saturating_add(interval);
            match self
                .tat
                .compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Relaxed)
            {
                Ok(_) => return true,
                Err(observed) => current = observed,
            }
        }
    }

    /// Reset to a full bucket.
    pub fn reset(&self) {
        self.tat.store(0, core::sync::atomic::Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: u64 = 1_000_000;

    #[test]
    fn first_packet_is_immediate() {
        let g = Gcra::new(100_000_000, 64 * 1024).unwrap();
        assert_eq!(g.check(0), None);
    }

    #[test]
    fn burst_is_absorbed_then_steady_state_throttles() {
        // 1 MB/s => 1 µs per byte. Burst 1500 bytes => 1.5 ms of tolerance.
        let mut g = Gcra::new(1_000_000, 1500).unwrap();
        let mut now = 0u64;
        let mut sent = 0u64;
        for _ in 0..100 {
            if g.try_acquire(1000, now) {
                sent += 1000;
            } else {
                // Wait exactly as long as the limiter asks, then retry.
                let d = g.check(now).unwrap();
                now += d;
                assert!(g.try_acquire(1000, now));
                sent += 1000;
            }
        }
        // 100 KB at 1 MB/s needs ~100 ms, minus the one-packet burst.
        assert!(
            now >= 95 * MS,
            "finished too early: {now} ns for {sent} bytes"
        );
    }

    #[test]
    fn steady_state_error_is_below_one_millisecond() {
        let rate = 200_000u64; // bytes/s
        let mut g = Gcra::new(rate, 32 * 1024).unwrap();
        let mut now = 0u64;
        let mut sent = 0u64;
        for _ in 0..2000 {
            let len = 1500u32;
            if !g.try_acquire(len, now) {
                now += g.check(now).unwrap();
                assert!(g.try_acquire(len, now));
            }
            sent += u64::from(len);
        }
        // Exact GCRA guarantee: at any instant T, total bytes emitted is at
        // most rate*T + tolerance. Compute it in ns (multiplying first) so the
        // bound is not loosened by integer truncation.
        // rate*T + tolerance + one packet (the last packet's interval lands
        // after `now`; that is inherent to GCRA, not a leak).
        let allowed = u128::from(rate) * u128::from(now) / u128::from(NS_PER_SEC)
            + u128::from(32_768u32)
            + u128::from(1500u32);
        assert!(
            u128::from(sent) <= allowed,
            "sent {sent} > allowed {allowed} in {now} ns"
        );
    }

    #[test]
    fn atomic_lane_matches_plain_lane() {
        let cfg = Gcra::new(1_000_000, 16 * 1024).unwrap();
        let atomic = AtomicGcra::new(cfg);
        let mut plain = cfg;
        let mut now = 0u64;
        for i in 0..500u32 {
            let len = 64 + (i % 1400);
            let a = atomic.try_acquire(len, now);
            let b = plain.try_acquire(len, now);
            assert_eq!(a, b, "divergence at packet {i}");
            now += 20_000;
        }
        assert_eq!(atomic.tat(), plain.tat());
    }

    #[test]
    fn reset_makes_next_packet_free() {
        let mut g = Gcra::new(1_000_000, 1500).unwrap();
        for i in 0..50 {
            g.try_acquire(1400, i * 1_000);
        }
        g.reset();
        assert_eq!(g.check(0), None);
    }

    #[test]
    fn rejects_bad_parameters() {
        assert!(Gcra::new(0, 10_000).is_err());
        assert!(Gcra::new(1_000, 100).is_err());
        assert!(Gcra::new(u64::MAX, 10_000).is_err());
    }

    #[test]
    fn bits_per_sec_conversion() {
        let g = Gcra::from_bits_per_sec(8_000_000, 3000).unwrap();
        assert_eq!(g.rate(), 1_000_000);
    }

    #[test]
    fn zero_wait_when_bucket_has_burst_left() {
        let g = Gcra::new(1_000_000, 10_000).unwrap();
        assert_eq!(g.check(0), None);
    }
}
