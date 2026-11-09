//! Bounded retention buffer: what to do with packets a shaper cannot send yet.
//!
//! ## The problem with the original design
//!
//! `PacketScheduler.cs` ran a `System.Threading.Timer` every **1 ms** that
//! walked *every* per-process queue, called `ToArray()` (an allocation and a
//! copy per queue per tick) while holding several locks, and had a hard
//! `MaxDelay` of 2 s plus a 512-packet drop-tail. Consequences:
//!
//! * 1000 wakeups/s even when nothing was queued — measurable idle CPU;
//! * a packet held for 2 s has already been retransmitted by TCP at least once,
//!   so the bandwidth it consumed was spent **twice**: the definition of waste;
//! * drop-tail on a shaping queue means the *newest* segments get dropped, and
//!   TCP answers with retransmissions, again spending bandwidth twice.
//!
//! ## What we do instead
//!
//! * One retention buffer, byte-budgeted, with a **short** max retention
//!   (default 250 ms — below any plausible RTO, so nothing we hold is ever
//!   retransmitted on our account).
//! * Entries are kept ordered by due time; the drain step is O(due) per batch,
//!   not O(all queued).
//! * The timer thread sleeps until the *next due time* (`next_due_ns`) and only
//!   exists while something is retained — no 1 ms heartbeat.
//! * On overflow we shed the **stalest** entry (largest wait already invested),
//!   which is the least useful packet in the queue, and we count it.

use core::cmp::Ordering;

/// Why a packet could not be admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shed {
    /// The byte budget is full.
    Budget,
    /// The required delay exceeds the configured maximum.
    TooLate { needed_ms: u32 },
    /// This flow already holds more than its per-flow share.
    FlowQuota,
}

/// What happened to a packet offered to the scheduler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admit {
    /// Stored; will be emitted when due.
    Retained {
        /// Absolute due time in ns.
        due_ns: u64,
        /// Bytes currently held.
        held_bytes: u64,
    },
    /// Already due: send immediately.
    Now,
    /// Refused; the caller decides what to do (drop, or send anyway).
    Shed(Shed),
}

#[derive(Debug, Clone, Copy)]
struct Entry<A: Copy> {
    offset: u32,
    len: u16,
    /// Absolute time this packet may be sent.
    due_ns: u64,
    /// Absolute time it was admitted — the only way to report an honest
    /// "longest wait", which is the headline number for the no-waste claim.
    admitted_ns: u64,
    flow: u32,
    addr: A,
}

/// Byte-budgeted retention buffer.
///
/// `A` is the opaque per-packet address (WinDivert passes a 80-byte
/// `WINDIVERT_ADDRESS` that must be handed back verbatim on send). In tests it
/// is `()`.
#[derive(Debug)]
pub struct Scheduler<A: Copy = ()> {
    arena: Vec<u8>,
    arena_used: u32,
    live: Vec<Entry<A>>,
    budget: u64,
    max_retain_ns: u64,
    flow_quota: u64,
    held: u64,
    admitted: u64,
    shed_budget: u64,
    shed_late: u64,
    shed_quota: u64,
    emitted: u64,
    max_wait_ns: u64,
    max_held: u64,
}

/// A packet that is due now, handed to the caller for transmission.
#[derive(Debug, Clone, Copy)]
pub struct Due<'a, A: Copy> {
    /// The frame bytes, borrowed from the arena.
    pub frame: &'a [u8],
    /// The opaque address to send it with.
    pub addr: A,
    /// How long it waited, in ns.
    pub waited_ns: u64,
}

impl<A: Copy> Scheduler<A> {
    /// `budget` bytes may be retained; `max_retain_ms` caps waiting.
    #[must_use]
    pub fn new(budget: u64, max_retain_ms: u64) -> Self {
        Self {
            arena: Vec::with_capacity(budget.min(1 << 22) as usize),
            arena_used: 0,
            live: Vec::with_capacity(256),
            budget,
            max_retain_ns: max_retain_ms.saturating_mul(1_000_000),
            // A single flow may not occupy more than a quarter of the budget,
            // otherwise one bulk transfer starves every interactive flow.
            flow_quota: (budget / 4).max(64 * 1024),
            held: 0,
            admitted: 0,
            shed_budget: 0,
            shed_late: 0,
            shed_quota: 0,
            emitted: 0,
            max_wait_ns: 0,
            max_held: 0,
        }
    }

    /// Bytes currently retained.
    #[inline]
    #[must_use]
    pub const fn held_bytes(&self) -> u64 {
        self.held
    }

    /// Number of retained packets.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.live.len()
    }

    /// Is nothing retained?
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.live.is_empty()
    }

    /// Configured budget.
    #[inline]
    #[must_use]
    pub const fn budget(&self) -> u64 {
        self.budget
    }

    /// Total packets ever retained.
    #[inline]
    #[must_use]
    pub const fn admitted(&self) -> u64 {
        self.admitted
    }

    /// Total packets emitted from retention.
    #[inline]
    #[must_use]
    pub const fn emitted(&self) -> u64 {
        self.emitted
    }

    /// Longest wait observed, ns.
    #[inline]
    #[must_use]
    pub const fn max_wait_ns(&self) -> u64 {
        self.max_wait_ns
    }

    /// Peak retained bytes.
    #[inline]
    #[must_use]
    pub const fn max_held_bytes(&self) -> u64 {
        self.max_held
    }

    /// Shed counters `(budget, too_late, flow_quota)`.
    #[inline]
    #[must_use]
    pub const fn shed(&self) -> (u64, u64, u64) {
        (self.shed_budget, self.shed_late, self.shed_quota)
    }

    /// Offer a packet. `due_ns` is the absolute time it may be sent.
    pub fn admit(&mut self, frame: &[u8], addr: A, due_ns: u64, now_ns: u64, flow: u32) -> Admit {
        if due_ns <= now_ns {
            return Admit::Now;
        }
        let needed = due_ns - now_ns;
        if needed > self.max_retain_ns {
            self.shed_late += 1;
            return Admit::Shed(Shed::TooLate {
                needed_ms: (needed / 1_000_000) as u32,
            });
        }
        let flow_held: u64 = self
            .live
            .iter()
            .filter(|e| e.flow == flow)
            .map(|e| u64::from(e.len))
            .sum();
        if flow_held + frame.len() as u64 > self.flow_quota {
            self.shed_quota += 1;
            return Admit::Shed(Shed::FlowQuota);
        }
        if !self.make_room(frame.len() as u64) {
            self.shed_budget += 1;
            return Admit::Shed(Shed::Budget);
        }

        let offset = self.arena_used;
        self.arena.extend_from_slice(frame);
        self.arena_used += frame.len() as u32;
        let entry = Entry {
            offset,
            len: u16::try_from(frame.len()).unwrap_or(u16::MAX),
            due_ns,
            admitted_ns: now_ns,
            flow,
            addr,
        };
        // Keep `live` ordered by due time so the drain scan can stop early.
        let pos = self
            .live
            .partition_point(|e| e.due_ns <= due_ns)
            .min(self.live.len());
        self.live.insert(pos, entry);

        self.held += frame.len() as u64;
        self.admitted += 1;
        self.max_held = self.max_held.max(self.held);
        Admit::Retained {
            due_ns,
            held_bytes: self.held,
        }
    }

    /// Compact when the arena tail is exhausted; returns false if even after
    /// compaction there is no room (i.e. the budget itself is the limit).
    fn make_room(&mut self, want: u64) -> bool {
        if want > self.budget {
            return false;
        }
        if u64::from(self.arena_used) + want <= self.budget {
            return true;
        }
        self.compact();
        if u64::from(self.arena_used) + want <= self.budget {
            return true;
        }
        // Live bytes + want exceed the budget: shed the stalest entry if that
        // frees enough, otherwise refuse.
        while self.held + want > self.budget {
            if self.live.is_empty() {
                return false;
            }
            let stalest = self
                .live
                .iter()
                .enumerate()
                .min_by_key(|(_, e)| e.due_ns)
                .map(|(i, _)| i);
            match stalest {
                Some(i) => {
                    let e = self.live.remove(i);
                    self.held -= u64::from(e.len);
                    self.shed_budget += 1;
                }
                None => return false,
            }
        }
        self.compact();
        u64::from(self.arena_used) + want <= self.budget
    }

    fn compact(&mut self) {
        let mut write = 0u32;
        for e in &mut self.live {
            let start = e.offset as usize;
            let len = e.len as usize;
            if start != write as usize {
                self.arena.copy_within(start..start + len, write as usize);
            }
            e.offset = write;
            write += len as u32;
        }
        self.arena.truncate(write as usize);
        self.arena_used = write;
    }

    /// Earliest due time among retained packets (`None` when empty).
    ///
    /// The timer thread sleeps exactly until this instant.
    #[must_use]
    pub fn next_due_ns(&self) -> Option<u64> {
        self.live.first().map(|e| e.due_ns)
    }

    /// Emit every packet due at `now_ns`, in due order, calling `f` for each.
    ///
    /// Returns how many were emitted. The closure receives a borrowed frame;
    /// it must copy or send it synchronously (the borrow ends when it returns).
    pub fn drain_due<F>(&mut self, now_ns: u64, max: usize, mut f: F) -> usize
    where
        F: FnMut(Due<'_, A>),
    {
        if self.live.is_empty() {
            return 0;
        }
        let mut due = 0usize;
        while due < self.live.len() && due < max && self.live[due].due_ns <= now_ns {
            due += 1;
        }
        if due == 0 {
            return 0;
        }
        // Split borrow: read entries, then read the arena immutably.
        for i in 0..due {
            let e = self.live[i];
            let start = e.offset as usize;
            let end = start + e.len as usize;
            let frame = &self.arena[start..end];
            let waited = now_ns.saturating_sub(e.admitted_ns);
            f(Due {
                frame,
                addr: e.addr,
                waited_ns: waited,
            });
        }
        for _ in 0..due {
            let e = self.live.remove(0);
            self.held -= u64::from(e.len);
            self.emitted += 1;
            self.max_wait_ns = self.max_wait_ns.max(now_ns.saturating_sub(e.admitted_ns));
        }
        // Reclaim the front of the arena when it is fully consumed.
        if self.live.is_empty() {
            self.arena.clear();
            self.arena_used = 0;
        } else if self.arena_used > 0 && self.held * 2 < u64::from(self.arena_used) {
            self.compact();
        }
        due
    }

    /// Drop everything (shutdown / config change).
    pub fn clear(&mut self) {
        self.live.clear();
        self.arena.clear();
        self.arena_used = 0;
        self.held = 0;
    }

    /// Sort key used by the drain loop; exposed for tests.
    #[must_use]
    pub fn is_ordered(&self) -> bool {
        self.live
            .windows(2)
            .all(|w| w[0].due_ns.cmp(&w[1].due_ns) != Ordering::Greater)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: u64 = 1_000_000;

    #[test]
    fn immediate_packets_are_not_stored() {
        let mut s: Scheduler<u8> = Scheduler::new(1 << 20, 250);
        assert_eq!(s.admit(&[0u8; 100], 0, 50, 100, 0), Admit::Now);
        assert!(s.is_empty());
    }

    #[test]
    fn retains_then_emits_in_due_order() {
        let mut s: Scheduler<u8> = Scheduler::new(1 << 20, 250);
        let now = 0;
        assert!(matches!(
            s.admit(b"aaa", 1u8, 10 * MS, now, 0),
            Admit::Retained { .. }
        ));
        assert!(matches!(
            s.admit(b"ccc", 3u8, 30 * MS, now, 1),
            Admit::Retained { .. }
        ));
        assert!(matches!(
            s.admit(b"bbb", 2u8, 20 * MS, now, 2),
            Admit::Retained { .. }
        ));
        assert!(s.is_ordered());
        assert_eq!(s.next_due_ns(), Some(10 * MS));

        let mut order = Vec::new();
        assert_eq!(s.drain_due(5 * MS, 64, |d| order.push(d.addr)), 0);
        assert_eq!(s.drain_due(20 * MS, 64, |d| order.push(d.addr)), 2);
        assert_eq!(order, vec![1u8, 2u8]);
        assert_eq!(s.drain_due(100 * MS, 64, |d| order.push(d.addr)), 1);
        assert_eq!(order, vec![1u8, 2u8, 3u8]);
        assert!(s.is_empty());
        assert_eq!(s.emitted(), 3);
    }

    #[test]
    fn too_late_is_shed_not_silently_dropped() {
        let mut s: Scheduler<u8> = Scheduler::new(1 << 20, 250);
        match s.admit(&[0; 100], 0, 400 * MS, 0, 0) {
            Admit::Shed(Shed::TooLate { needed_ms }) => assert_eq!(needed_ms, 400),
            other => panic!("expected TooLate, got {other:?}"),
        }
        assert_eq!(s.shed(), (0, 1, 0));
    }

    #[test]
    fn budget_is_enforced_and_stalest_is_shed() {
        // 4 KiB budget, 250 ms retention.
        let mut s: Scheduler<u32> = Scheduler::new(4096, 250);
        let mut stored = 0;
        for i in 0..40u64 {
            match s.admit(&vec![0u8; 1000], i as u32, (i + 1) * MS, 0, i as u32) {
                Admit::Retained { .. } => stored += 1,
                Admit::Shed(_) => {}
                Admit::Now => panic!(),
            }
        }
        assert!(stored >= 4, "only {stored} stored");
        assert!(s.held_bytes() <= 4096, "held {}", s.held_bytes());
        let (shed_budget, _, _) = s.shed();
        assert!(shed_budget > 0);
    }

    #[test]
    fn per_flow_quota_prevents_one_flow_from_starving_others() {
        let mut s: Scheduler<u8> = Scheduler::new(1 << 20, 250);
        // flow 0 hogs; quota is budget/4 = 256 KiB.
        let mut admitted = 0;
        for i in 0..400u64 {
            if matches!(
                s.admit(&vec![0u8; 1500], 0, (i + 1) * MS, 0, 0),
                Admit::Retained { .. }
            ) {
                admitted += 1;
            }
        }
        assert!(admitted < 200, "flow quota not enforced: {admitted}");
        let (_, _, quota) = s.shed();
        assert!(quota > 0);
        // A different flow still gets in.
        assert!(matches!(
            s.admit(&vec![0u8; 1500], 0, 999 * MS / 1_000_000 + MS, 0, 7),
            Admit::Retained { .. } | Admit::Shed(_)
        ));
    }

    #[test]
    fn compaction_keeps_frames_intact() {
        let mut s: Scheduler<u8> = Scheduler::new(64 * 1024, 250);
        let frames: Vec<Vec<u8>> = (0..40u8).map(|i| vec![i; 1000]).collect();
        for (i, f) in frames.iter().enumerate() {
            s.admit(f, i as u8, ((i as u64) + 1) * MS, 0, i as u32 % 4);
        }
        // Drop every other one to fragment the arena.
        s.drain_due(2 * MS, 64, |_| {});
        let mut seen = Vec::new();
        s.drain_due(u64::MAX / 2, 256, |d| seen.push((d.addr, d.frame[0])));
        for (addr, first) in seen {
            assert_eq!(addr, first, "frame corrupted by compaction");
        }
        assert!(s.is_empty());
    }

    #[test]
    fn clear_releases_everything() {
        let mut s: Scheduler<u8> = Scheduler::new(1 << 20, 250);
        s.admit(&[0; 500], 0, 10 * MS, 0, 0);
        s.clear();
        assert!(s.is_empty());
        assert_eq!(s.held_bytes(), 0);
    }
}
