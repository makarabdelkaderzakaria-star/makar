//! Monotonic nanosecond clock with a cached base.
//!
//! One `Instant::now()` per *batch* rather than per packet, and a plain
//! additive conversion afterwards. `Instant::now()` is a `QueryPerformanceCounter`
//! call on Windows — cheap, but not free, and the original called the managed
//! equivalent several times per packet through `Stopwatch`/`DateTime`.

use std::time::Instant;

/// A monotonic clock anchored at construction.
#[derive(Debug)]
pub struct Clock {
    base: Instant,
}

impl Default for Clock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock {
    /// Anchor the clock.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Instant::now(),
        }
    }

    /// Nanoseconds since the clock was created.
    #[inline]
    #[must_use]
    pub fn now_ns(&self) -> u64 {
        // `as_nanos` is a u128; the cast is safe for ~584 years of uptime.
        self.base.elapsed().as_nanos() as u64
    }

    /// Milliseconds since the clock was created.
    #[inline]
    #[must_use]
    pub fn now_ms(&self) -> u64 {
        self.now_ns() / 1_000_000
    }

    /// Re-anchor if the process has been running long enough to risk overflow
    /// (never in practice, but a cheap invariant to keep).
    pub fn maybe_reanchor(&mut self) {
        if self.now_ns() > (1u64 << 62) {
            self.base = Instant::now();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clock_is_monotonic() {
        let c = Clock::new();
        let a = c.now_ns();
        std::thread::yield_now();
        let b = c.now_ns();
        assert!(b >= a);
    }

    #[test]
    fn ms_and_ns_agree() {
        let c = Clock::new();
        let ns = c.now_ns();
        let ms = c.now_ms();
        assert!(ms <= ns / 1_000_000 + 1);
    }
}
