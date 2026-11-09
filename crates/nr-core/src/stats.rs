//! Statistics: plain counters, no atomics on the hot path.
//!
//! The engine is single-threaded by design (one reader thread owns it), so all
//! counters are plain `u64` fields incremented without fences. That is a
//! deliberate choice: `Interlocked.Increment` per packet, as the original did
//! for several counters, is a locked instruction on a shared cache line and
//! shows up in profiles at tens of thousands of packets per second.
//!
//! Cross-thread visibility is obtained by *publishing a snapshot* (a `Copy`
//! struct) once per second, which is what the TUI and the IPC layer consume.

use crate::flow::FlowTable;
use crate::scheduler::Scheduler;

/// Live counters owned by the engine.
#[derive(Debug, Default, Clone, Copy)]
pub struct Counters {
    /// Packets seen.
    pub packets: u64,
    /// Bytes seen (IP length).
    pub bytes: u64,
    /// Outbound packets.
    pub out_packets: u64,
    /// Inbound packets.
    pub in_packets: u64,
    /// Packets forwarded with no rule applied.
    pub unmatched: u64,
    /// Packets explicitly allowed by a rule.
    pub allowed: u64,
    /// Packets attributed through the rule table (not the cache).
    pub rule_hits: u64,
    /// Packets that conformed to their limit.
    pub rate_ok: u64,
    /// Packets that did not conform.
    pub rate_over: u64,
    /// Packets put in the retention buffer.
    pub retained: u64,
    /// Packets emitted from the retention buffer.
    pub emitted_from_retention: u64,
    /// Dropped by a `block` rule.
    pub dropped_blocked: u64,
    /// Dropped by an over-limit `drop` policy.
    pub dropped_policy: u64,
    /// Dropped because the required delay exceeded the ceiling.
    pub dropped_late: u64,
    /// Dropped because the retention byte budget was full.
    pub dropped_budget: u64,
    /// Dropped because a single flow hit its retention quota.
    pub dropped_quota: u64,
    /// Dropped because a limit's byte budget (cap) is spent for this period.
    pub dropped_cap: u64,
    /// Forwarded with the CE codepoint set instead of being delayed or dropped.
    pub marked_ecn: u64,
    /// Dropped as unparseable (still forwarded; counted for visibility).
    pub dropped_malformed: u64,
    /// New flow rows created.
    pub flows_created: u64,
    /// Packets whose flow could not be tracked (table full).
    pub flows_refused: u64,
}

impl Counters {
    /// Total packets the engine refused to forward.
    #[must_use]
    pub const fn dropped_total(&self) -> u64 {
        self.dropped_blocked
            + self.dropped_policy
            + self.dropped_late
            + self.dropped_budget
            + self.dropped_quota
            + self.dropped_cap
    }
}

/// Immutable, `Copy` snapshot published to other threads once per second.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Snapshot {
    /// Monotonic timestamp of the snapshot (ms).
    pub at_ms: u64,
    /// See [`Counters::packets`].
    pub packets: u64,
    /// See [`Counters::bytes`].
    pub bytes: u64,
    /// See [`Counters::out_packets`].
    pub out_packets: u64,
    /// See [`Counters::in_packets`].
    pub in_packets: u64,
    /// See [`Counters::unmatched`].
    pub unmatched: u64,
    /// See [`Counters::allowed`].
    pub allowed: u64,
    /// See [`Counters::rule_hits`].
    pub rule_hits: u64,
    /// See [`Counters::rate_ok`].
    pub rate_ok: u64,
    /// See [`Counters::rate_over`].
    pub rate_over: u64,
    /// See [`Counters::retained`].
    pub retained: u64,
    /// See [`Counters::emitted_from_retention`].
    pub emitted_from_retention: u64,
    /// See [`Counters::dropped_blocked`].
    pub dropped_blocked: u64,
    /// See [`Counters::dropped_policy`].
    pub dropped_policy: u64,
    /// See [`Counters::dropped_late`].
    pub dropped_late: u64,
    /// See [`Counters::dropped_budget`].
    pub dropped_budget: u64,
    /// See [`Counters::dropped_quota`].
    pub dropped_quota: u64,
    /// See [`Counters::dropped_cap`].
    pub dropped_cap: u64,
    /// See [`Counters::marked_ecn`].
    pub marked_ecn: u64,
    /// Live flows.
    pub flows: u64,
    /// Flow table capacity.
    pub flows_capacity: u64,
    /// Bytes currently retained.
    pub retained_bytes: u64,
    /// Peak retained bytes.
    pub retained_peak: u64,
    /// Longest wait a packet experienced, ns.
    pub max_wait_ns: u64,
    /// Configured retention budget.
    pub retain_budget: u64,
    /// Packets the retention buffer itself evicted to make room (already
    /// admitted, then displaced by a newer packet). Counted separately from
    /// engine drops so that the accounting closes exactly:
    ///
    /// `packets == forwarded + dropped_total + retained_shed + retained_left`
    pub retained_shed: u64,
    /// Packets still sitting in the retention buffer right now.
    pub retained_left: u64,
    /// Of `retained_shed`, how many CoDel dropped on purpose because the queue
    /// was standing above its target (0 when CoDel is off).
    pub retained_codel: u64,
}

impl Snapshot {
    /// Total dropped (all reasons).
    #[must_use]
    pub const fn dropped_total(&self) -> u64 {
        self.dropped_blocked
            + self.dropped_policy
            + self.dropped_late
            + self.dropped_budget
            + self.dropped_quota
            + self.dropped_cap
    }

    /// Difference against a previous snapshot, for rate display.
    #[must_use]
    pub fn delta(&self, prev: &Self) -> Delta {
        let dt = self.at_ms.saturating_sub(prev.at_ms).max(1);
        Delta {
            ms: dt,
            packets: self.packets.saturating_sub(prev.packets),
            bytes: self.bytes.saturating_sub(prev.bytes),
            dropped: self.dropped_total().saturating_sub(prev.dropped_total()),
            retained: self
                .emitted_from_retention
                .saturating_sub(prev.emitted_from_retention),
        }
    }
}

/// Per-interval deltas used by the TUI.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Delta {
    /// Interval length in ms.
    pub ms: u64,
    /// Packets in the interval.
    pub packets: u64,
    /// Bytes in the interval.
    pub bytes: u64,
    /// Drops in the interval.
    pub dropped: u64,
    /// Packets emitted from retention in the interval.
    pub retained: u64,
}

impl Delta {
    /// Packets per second.
    #[must_use]
    pub fn pps(&self) -> u64 {
        self.packets.saturating_mul(1000) / self.ms
    }

    /// Bytes per second (multiply by 8 for bits; `human_bps` does that).
    #[must_use]
    pub fn bytes_per_sec(&self) -> u64 {
        self.bytes.saturating_mul(1000) / self.ms
    }
}

impl Counters {
    /// Build a snapshot from the counters plus table state.
    #[must_use]
    pub fn snapshot<const CAP: usize, A: Copy>(
        &self,
        flows: &FlowTable<CAP>,
        scheduler: &Scheduler<A>,
    ) -> Snapshot {
        Snapshot {
            at_ms: 0,
            packets: self.packets,
            bytes: self.bytes,
            out_packets: self.out_packets,
            in_packets: self.in_packets,
            unmatched: self.unmatched,
            allowed: self.allowed,
            rule_hits: self.rule_hits,
            rate_ok: self.rate_ok,
            rate_over: self.rate_over,
            retained: self.retained,
            emitted_from_retention: self.emitted_from_retention,
            dropped_blocked: self.dropped_blocked,
            dropped_policy: self.dropped_policy,
            dropped_late: self.dropped_late,
            dropped_budget: self.dropped_budget,
            dropped_quota: self.dropped_quota,
            dropped_cap: self.dropped_cap,
            marked_ecn: self.marked_ecn,
            flows: flows.len() as u64,
            flows_capacity: flows.capacity() as u64,
            retained_bytes: scheduler.held_bytes(),
            retained_peak: scheduler.max_held_bytes(),
            max_wait_ns: scheduler.max_wait_ns(),
            retain_budget: scheduler.budget(),
            // CoDel drops come out of the same buffer, so they belong in the
            // same total: the accounting identity in the field docs must keep
            // holding with CoDel armed or off.
            retained_shed: {
                let (a, b, c) = scheduler.shed();
                a + b + c + scheduler.codel_drops()
            },
            retained_left: scheduler.len() as u64,
            retained_codel: scheduler.codel_drops(),
        }
    }
}

/// Format a byte rate for humans: `1.25 Mbit/s`.
#[must_use]
pub fn human_bps(bytes_per_sec: u64) -> String {
    let bits = bytes_per_sec.saturating_mul(8);
    if bits >= 1_000_000_000 {
        format!("{:.2} Gbit/s", bits as f64 / 1e9)
    } else if bits >= 1_000_000 {
        format!("{:.2} Mbit/s", bits as f64 / 1e6)
    } else if bits >= 1_000 {
        format!("{:.1} kbit/s", bits as f64 / 1e3)
    } else {
        format!("{bits} bit/s")
    }
}

/// Format a byte count: `1.44 MB`.
#[must_use]
pub fn human_bytes(bytes: u64) -> String {
    if bytes >= 1_000_000_000 {
        format!("{:.2} GB", bytes as f64 / 1e9)
    } else if bytes >= 1_000_000 {
        format!("{:.2} MB", bytes as f64 / 1e6)
    } else if bytes >= 1_000 {
        format!("{:.1} KB", bytes as f64 / 1e3)
    } else {
        format!("{bytes} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_formats() {
        assert_eq!(human_bps(1_000_000), "8.00 Mbit/s");
        assert_eq!(human_bps(125), "1.0 kbit/s");
        assert_eq!(human_bytes(1_500_000), "1.50 MB");
        assert_eq!(human_bytes(999), "999 B");
    }

    #[test]
    fn deltas_are_saturating() {
        let prev = Snapshot {
            at_ms: 1000,
            packets: 200,
            bytes: 2000,
            ..Snapshot::default()
        };
        let now = Snapshot {
            at_ms: 2000,
            packets: 100,
            bytes: 1000,
            ..Snapshot::default()
        };
        // Deltas against a *newer* previous snapshot saturate at zero rather
        // than underflowing, which is what the TUI relies on after a restart.
        assert_eq!(now.delta(&prev).packets, 0);
        let d = now.delta(&Snapshot {
            at_ms: 500,
            packets: 0,
            bytes: 0,
            ..Snapshot::default()
        });
        assert_eq!(d.packets, 100);
        assert_eq!(d.ms, 1500);
        assert_eq!(d.pps(), 66);
        assert_eq!(d.bytes_per_sec(), 666);
    }
}
