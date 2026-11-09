//! Flow attribution: "which process owns this 5-tuple?"
//!
//! The network layer of WinDivert carries no PID (the `WINDIVERT_ADDRESS` union
//! holds only `IfIdx`/`SubIfIdx` for `NETWORK`), so attribution has to come
//! from a second handle on the **FLOW** or **SOCKET** layer, which does report
//! a `ProcessId`.
//!
//! Two facts shape this module:
//!
//! 1. A FLOW handle only reports flows created *after* it is opened. Traffic
//!    that already existed is therefore unattributed, and the only honest
//!    options are a warm-up window or an explicit "unknown" policy. We do the
//!    latter: an unknown flow keeps no identity and no name-based rule matches
//!    it, which is visible in the counters instead of silently mis-attributing.
//! 2. PIDs are recycled, so a flow is attributed to `(pid, start_time)`, not to
//!    a bare PID.
//!
//! This type is pure data plus a small hash table, so the whole attribution
//! policy is testable on Linux even though its only real producer is Windows.

use crate::flow::Endpoint;
use crate::flow::FlowKey;
use crate::identity::ProcKey;
use crate::packet::Protocol;

/// What we know about the process that owns a flow.
pub type Owner = ProcKey;

/// A FLOW-layer event, normalised away from the WinDivert struct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowEvent {
    /// The owner of the flow.
    pub key: ProcKey,
    /// Driver's endpoint id (stable for the lifetime of the endpoint).
    pub endpoint_id: u64,
    /// Protocol number (6 TCP, 17 UDP, ...).
    pub protocol: u8,
    /// Local endpoint.
    pub local: Endpoint,
    /// Remote endpoint.
    pub remote: Endpoint,
    /// `true` for FLOW_ESTABLISHED / SOCKET_CONNECT, `false` for deletion.
    pub established: bool,
}

impl FlowEvent {
    /// The canonical flow key this event describes.
    ///
    /// The same key the packet path computes, so attribution is a single hash
    /// lookup with no reversal step (the original retried with a reversed key
    /// for every inbound packet).
    #[must_use]
    pub fn flow_key(&self) -> FlowKey {
        let (a, b) = if self.local <= self.remote {
            (self.local, self.remote)
        } else {
            (self.remote, self.local)
        };
        FlowKey {
            a,
            b,
            protocol: Protocol::from_ip(self.protocol),
            pid: self.key.pid,
        }
    }
}

/// One pre-existing endpoint discovered at start-up.
///
/// A FLOW handle only reports flows created *after* it is opened, so everything
/// already running when NetRocket starts is invisible to it. The mitigation is
/// to ask the operating system for the current endpoint table and seed
/// attribution with it — `GetExtendedTcpTable`/`GetExtendedUdpTable` on Windows.
///
/// A listening socket has no meaningful remote address (`0.0.0.0:0`); those are
/// stored as *PID-only* hints, because inventing a 5-tuple for them would
/// attribute the wrong flows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotEntry {
    /// Owning process.
    pub key: ProcKey,
    /// Protocol number (6 TCP, 17 UDP).
    pub protocol: u8,
    /// Local address and port.
    pub local: Endpoint,
    /// Remote address and port, or [`Endpoint::unspecified`] for a listener.
    pub remote: Endpoint,
}

impl SnapshotEntry {
    /// A connected endpoint.
    #[must_use]
    pub const fn connected(key: ProcKey, protocol: u8, local: Endpoint, remote: Endpoint) -> Self {
        Self {
            key,
            protocol,
            local,
            remote,
        }
    }

    /// A listening endpoint: no remote, so only the PID hint can be used.
    #[must_use]
    pub const fn listening(key: ProcKey, protocol: u8, local: Endpoint) -> Self {
        Self {
            key,
            protocol,
            local,
            remote: Endpoint::unspecified(),
        }
    }

    /// Is this a listener (no remote endpoint)?
    #[must_use]
    pub const fn is_listener(&self) -> bool {
        self.remote.port == 0
    }
}

/// What a seed pass achieved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SeedReport {
    /// Connected endpoints stored in the 5-tuple table.
    pub connected: usize,
    /// Listening endpoints stored as PID-only hints.
    pub listeners: usize,
    /// Entries skipped (no PID, or a tuple we cannot represent).
    pub skipped: usize,
}

impl SeedReport {
    /// Total entries considered.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.connected + self.listeners + self.skipped
    }
}

/// Fixed-capacity attribution table with TTL and endpoint-id aliasing.
///
/// Three lookups matter on the packet path:
///
/// * by canonical 5-tuple — the normal case;
/// * by endpoint id — cheap, survives a port change on the same socket;
/// * by PID — used when a FLOW event arrives before the first packet.
///
/// All three are O(1)-ish over a fixed array, and none of them allocate.
#[derive(Debug)]
pub struct FlowAttribution {
    slots: Vec<Option<Slot>>,
    by_endpoint: Vec<Option<EndpointSlot>>,
    by_pid: Vec<Option<PidSlot>>,
    mask: usize,
    ep_mask: usize,
    pid_mask: usize,
    ttl_ms: u64,
    hits: u64,
    misses: u64,
    inserts: u64,
    removals: u64,
}

#[derive(Debug, Clone, Copy)]
struct Slot {
    key: FlowKey,
    owner: Owner,
    expires_ms: u64,
}

impl Slot {
    /// Compare only the 5-tuple, **not** the PID.
    ///
    /// That is the whole point of this table: the packet path knows the tuple
    /// and is asking who owns it, so a lookup key can only ever carry
    /// `pid = 0`. Comparing the PID here would make every lookup miss — a bug
    /// the test `snapshots_match_packet_path_keys` in `nr-divert` exists to
    /// catch, because it builds a real packet and a real table row.
    fn same_tuple(&self, key: &FlowKey) -> bool {
        self.key.protocol == key.protocol
            && ((self.key.a == key.a && self.key.b == key.b)
                || (self.key.a == key.b && self.key.b == key.a))
    }
}

#[derive(Debug, Clone, Copy)]
struct EndpointSlot {
    endpoint_id: u64,
    owner: Owner,
    expires_ms: u64,
}

#[derive(Debug, Clone, Copy)]
struct PidSlot {
    pid: u32,
    owner: Owner,
    expires_ms: u64,
}

impl FlowAttribution {
    /// Create tables holding up to `capacity` flows.
    #[must_use]
    pub fn new(capacity: usize, ttl_ms: u64) -> Self {
        let cap = capacity.next_power_of_two().max(16);
        let ep = (cap / 4).next_power_of_two().max(16);
        let pid = (cap / 16).next_power_of_two().max(16);
        Self {
            slots: vec![None; cap],
            by_endpoint: vec![None; ep],
            by_pid: vec![None; pid],
            mask: cap - 1,
            ep_mask: ep - 1,
            pid_mask: pid - 1,
            ttl_ms,
            hits: 0,
            misses: 0,
            inserts: 0,
            removals: 0,
        }
    }

    /// Counters `(hits, misses, inserts, removals)`.
    #[must_use]
    pub const fn stats(&self) -> (u64, u64, u64, u64) {
        (self.hits, self.misses, self.inserts, self.removals)
    }

    /// Live entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.slots.iter().flatten().count()
    }

    /// Empty?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Slot hash over the **5-tuple only**.
    ///
    /// The PID is deliberately excluded. A lookup on the packet path carries
    /// `pid = 0` (the whole question is *which* PID owns this tuple), so mixing
    /// the PID in would send the same tuple to a different slot on insert than
    /// on lookup, and every attribution would miss. The test
    /// `snapshots_match_packet_path_keys` in `nr-divert` guards this, because a
    /// hash/lookup mismatch stays invisible until a real packet arrives.
    /// Slot hash over the **5-tuple only**, and order-independent.
    ///
    /// Two properties are load-bearing:
    ///
    /// * **The PID is excluded.** A lookup on the packet path carries
    ///   `pid = 0` — the whole question is *which* PID owns this tuple — so
    ///   mixing the PID in would hash the same tuple to a different slot on
    ///   insert than on lookup and every attribution would miss.
    /// * **The endpoint order does not matter.** A snapshot row or a FLOW event
    ///   may name the endpoints in the opposite order from a packet, so the two
    ///   halves are combined with `wrapping_add` (commutative) rather than a
    ///   rotation or a multiply chain.
    fn slot_of(key: &FlowKey) -> usize {
        fn half(e: &Endpoint) -> u64 {
            let mut h = u64::from(e.port).wrapping_mul(0x9E37_79B9_7F4A_7C15);
            for (i, b) in e.addr.iter().enumerate() {
                h = h
                    .wrapping_mul(31)
                    .wrapping_add(u64::from(*b) << (i % 8 * 8));
            }
            h
        }
        let h = half(&key.a).wrapping_add(half(&key.b));
        let mixed =
            (h ^ ((key.protocol as u64) << 56) ^ (h >> 29)).wrapping_mul(0xD6E8_FEB8_6659_FD93);
        (mixed ^ (mixed >> 32)) as usize
    }

    /// Test-only view of the slot hash (see `debug_probe`).
    #[cfg(test)]
    pub(crate) fn slot_of_for_test(key: &FlowKey) -> usize {
        Self::slot_of(key)
    }

    /// Attribute a flow. Returns `None` when it was never announced.
    #[must_use]
    pub fn get(&mut self, key: &FlowKey, now_ms: u64) -> Option<Owner> {
        let start = Self::slot_of(key) & self.mask;
        for i in 0..self.slots.len() {
            let idx = (start + i) & self.mask;
            match &self.slots[idx] {
                None => break,
                Some(s) => {
                    if now_ms >= s.expires_ms {
                        continue;
                    }
                    // Compare the 5-tuple only: the caller is asking *who owns
                    // this tuple*, so its key can only carry `pid = 0`.
                    if s.same_tuple(key) {
                        self.hits += 1;
                        return Some(s.owner);
                    }
                }
            }
        }
        self.misses += 1;
        None
    }

    /// Attribute by PID when the 5-tuple is not yet known.
    #[must_use]
    pub fn by_pid(&mut self, pid: u32, now_ms: u64) -> Option<Owner> {
        let idx = (pid as usize) & self.pid_mask;
        match self.by_pid[idx] {
            Some(s) if s.pid == pid && now_ms < s.expires_ms => Some(s.owner),
            _ => None,
        }
    }

    /// Attribute by driver endpoint id.
    #[must_use]
    pub fn by_endpoint(&mut self, endpoint_id: u64, now_ms: u64) -> Option<Owner> {
        let idx = (endpoint_id as usize) & self.ep_mask;
        match self.by_endpoint[idx] {
            Some(s) if s.endpoint_id == endpoint_id && now_ms < s.expires_ms => Some(s.owner),
            _ => None,
        }
    }

    /// Seed the table from a snapshot of endpoints that already exist.
    ///
    /// Call this **once**, right after opening the FLOW handle and before the
    /// network handle: it shrinks the window in which pre-existing traffic is
    /// unattributed to the gap between the two calls, instead of "until the
    /// connection is re-established".
    ///
    /// Entries without a PID are skipped, as are listeners in the 5-tuple table
    /// (they get a PID-only hint instead). Nothing is guessed.
    pub fn seed<I>(&mut self, entries: I, now_ms: u64) -> SeedReport
    where
        I: IntoIterator<Item = SnapshotEntry>,
    {
        let mut report = SeedReport::default();
        for e in entries {
            if e.key.pid == 0 {
                report.skipped += 1;
                continue;
            }
            // A PID hint is always useful: it lets a packet that arrives before
            // its FLOW event still be attributed to the right process.
            let pid_idx = (e.key.pid as usize) & self.pid_mask;
            self.by_pid[pid_idx] = Some(PidSlot {
                pid: e.key.pid,
                owner: e.key,
                expires_ms: now_ms.saturating_add(self.ttl_ms),
            });

            if e.is_listener() {
                report.listeners += 1;
                continue;
            }
            let key = key_of(e.local, e.remote, Protocol::from_ip(e.protocol), e.key.pid);
            self.insert(key, e.key, now_ms);
            report.connected += 1;
        }
        report
    }

    /// Record a FLOW/SOCKET event. Removal events evict rather than insert.
    pub fn apply(&mut self, ev: &FlowEvent, now_ms: u64) {
        if !ev.established {
            self.remove(&ev.flow_key());
            let idx = (ev.endpoint_id as usize) & self.ep_mask;
            if matches!(self.by_endpoint[idx], Some(s) if s.endpoint_id == ev.endpoint_id) {
                self.by_endpoint[idx] = None;
            }
            return;
        }
        self.insert(ev.flow_key(), ev.key, now_ms);

        let ep_idx = (ev.endpoint_id as usize) & self.ep_mask;
        self.by_endpoint[ep_idx] = Some(EndpointSlot {
            endpoint_id: ev.endpoint_id,
            owner: ev.key,
            expires_ms: now_ms.saturating_add(self.ttl_ms),
        });
        let pid_idx = (ev.key.pid as usize) & self.pid_mask;
        self.by_pid[pid_idx] = Some(PidSlot {
            pid: ev.key.pid,
            owner: ev.key,
            expires_ms: now_ms.saturating_add(self.ttl_ms),
        });
    }

    /// Insert or refresh a single mapping.
    pub fn insert(&mut self, key: FlowKey, owner: Owner, now_ms: u64) {
        let start = Self::slot_of(&key) & self.mask;
        let expires = now_ms.saturating_add(self.ttl_ms);
        let mut victim: Option<usize> = None;
        for i in 0..self.slots.len() {
            let idx = (start + i) & self.mask;
            match &self.slots[idx] {
                None => {
                    self.slots[idx] = Some(Slot {
                        key,
                        owner,
                        expires_ms: expires,
                    });
                    self.inserts += 1;
                    return;
                }
                Some(s) if s.key == key => {
                    self.slots[idx] = Some(Slot {
                        key,
                        owner,
                        expires_ms: expires,
                    });
                    self.inserts += 1;
                    return;
                }
                Some(s) => {
                    // Remember the first expired slot; it is the cheapest
                    // victim if we run out of room.
                    if victim.is_none() && now_ms >= s.expires_ms {
                        victim = Some(idx);
                    }
                }
            }
        }
        let idx = victim.unwrap_or(start);
        self.slots[idx] = Some(Slot {
            key,
            owner,
            expires_ms: expires,
        });
        self.inserts += 1;
    }

    /// Drop one mapping (TCP FIN/RST, or FLOW_DELETED).
    pub fn remove(&mut self, key: &FlowKey) -> bool {
        let start = Self::slot_of(key) & self.mask;
        for i in 0..self.slots.len() {
            let idx = (start + i) & self.mask;
            match &self.slots[idx] {
                None => return false,
                Some(s) if s.key == *key => {
                    self.slots[idx] = None;
                    self.removals += 1;
                    return true;
                }
                Some(_) => {}
            }
        }
        false
    }

    /// Expire everything older than the TTL. Called from the slow tick.
    pub fn sweep(&mut self, now_ms: u64) -> usize {
        let mut n = 0;
        for slot in &mut self.slots {
            if matches!(slot, Some(s) if now_ms >= s.expires_ms) {
                *slot = None;
                n += 1;
            }
        }
        for slot in &mut self.by_endpoint {
            if matches!(slot, Some(s) if now_ms >= s.expires_ms) {
                *slot = None;
            }
        }
        for slot in &mut self.by_pid {
            if matches!(slot, Some(s) if now_ms >= s.expires_ms) {
                *slot = None;
            }
        }
        n
    }
}

/// Build the canonical key for a packet's 5-tuple, for use with
/// [`FlowAttribution`] from the packet path.
#[must_use]
pub fn key_of(local: Endpoint, remote: Endpoint, protocol: Protocol, pid: u32) -> FlowKey {
    let (a, b) = if local <= remote {
        (local, remote)
    } else {
        (remote, local)
    };
    FlowKey {
        a,
        b,
        protocol,
        pid,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(addr: [u8; 4], port: u16) -> Endpoint {
        let mut a = [0u8; 16];
        a[..4].copy_from_slice(&addr);
        Endpoint { addr: a, port }
    }

    fn event(pid: u32, start: u64) -> FlowEvent {
        FlowEvent {
            key: ProcKey::new(pid, start),
            endpoint_id: 7,
            protocol: 6,
            local: ep([10, 0, 0, 1], 51515),
            remote: ep([1, 1, 1, 1], 443),
            established: true,
        }
    }

    #[test]
    fn event_key_matches_the_packet_path() {
        let ev = event(100, 5);
        let from_event = ev.flow_key();
        // Same 5-tuple computed the other way round must be identical.
        let from_packet = key_of(ev.remote, ev.local, Protocol::Tcp, 100);
        assert_eq!(from_event, from_packet);
    }

    #[test]
    fn established_then_lookup_then_removed() {
        let mut t = FlowAttribution::new(64, 60_000);
        let ev = event(100, 5);
        assert_eq!(t.get(&ev.flow_key(), 0), None);
        t.apply(&ev, 0);
        assert_eq!(t.get(&ev.flow_key(), 10), Some(ProcKey::new(100, 5)));
        assert_eq!(t.by_pid(100, 10), Some(ProcKey::new(100, 5)));
        assert_eq!(t.by_endpoint(7, 10), Some(ProcKey::new(100, 5)));

        let mut del = ev;
        del.established = false;
        t.apply(&del, 20);
        assert_eq!(t.get(&ev.flow_key(), 21), None);
        assert_eq!(t.by_endpoint(7, 21), None);
        let (hits, misses, inserts, removals) = t.stats();
        assert_eq!((hits, misses, inserts, removals), (1, 2, 1, 1));
    }

    #[test]
    fn reverse_direction_resolves_too() {
        let mut t = FlowAttribution::new(64, 60_000);
        let ev = event(200, 9);
        t.apply(&ev, 0);
        let mut reversed = ev.flow_key();
        core::mem::swap(&mut reversed.a, &mut reversed.b);
        assert_eq!(t.get(&reversed, 1), Some(ProcKey::new(200, 9)));
    }

    #[test]
    fn entries_expire() {
        let mut t = FlowAttribution::new(64, 1_000);
        let ev = event(300, 1);
        t.apply(&ev, 0);
        assert!(t.get(&ev.flow_key(), 500).is_some());
        assert!(t.get(&ev.flow_key(), 2_000).is_none());
        assert_eq!(t.sweep(2_000), 1);
        assert!(t.is_empty());
    }

    #[test]
    fn a_full_table_replaces_an_expired_slot_instead_of_growing() {
        let mut t = FlowAttribution::new(16, 100);
        for i in 0..200u32 {
            let mut ev = event(1000 + i, 1);
            ev.local = ep([10, 0, 0, (i % 250) as u8], 1000 + i as u16);
            ev.remote = ep([1, 1, 1, 1], 443);
            t.apply(&ev, i as u64 * 1_000);
        }
        assert!(t.len() <= 16, "table grew past its capacity: {}", t.len());
    }

    #[test]
    fn pid_reuse_is_a_different_owner() {
        let mut t = FlowAttribution::new(64, 60_000);
        let first = event(500, 111);
        t.apply(&first, 0);
        // Same PID, different creation time: the second replaces the mapping.
        let second = event(500, 222);
        t.apply(&second, 100);
        assert_eq!(t.get(&second.flow_key(), 200), Some(ProcKey::new(500, 222)));
    }
}

/// Regression tests for the two ways attribution silently stops working.
///
/// Both bugs are invisible without a test that stores a tuple the way a FLOW
/// event or a snapshot does and looks it up the way a packet does.
#[cfg(test)]
mod attr_regressions {
    use super::*;

    #[test]
    fn seeded_tuple_is_found_with_pid_zero_lookup() {
        let mut a = [0u8; 16];
        a[..4].copy_from_slice(&[10, 0, 0, 1]);
        let mut b = [0u8; 16];
        b[..4].copy_from_slice(&[1, 1, 1, 1]);
        let local = Endpoint {
            addr: a,
            port: 51515,
        };
        let remote = Endpoint { addr: b, port: 443 };
        let owner = ProcKey::new(4242, 0);
        let stored = key_of(local, remote, Protocol::Tcp, owner.pid);
        let looked_up = key_of(local, remote, Protocol::Tcp, 0);

        let mut t = FlowAttribution::new(64, 60_000);
        t.insert(stored, owner, 0);
        assert_eq!(t.len(), 1);
        // 1. does the hash match? (it must ignore the PID, because a lookup
        //    cannot know it)
        assert_eq!(
            FlowAttribution::slot_of_for_test(&stored),
            FlowAttribution::slot_of_for_test(&looked_up),
            "hash must ignore the pid"
        );
        // 2. does the tuple comparison match?
        assert!(
            stored.is_reverse_of(&looked_up) || stored == looked_up || {
                stored.a == looked_up.a && stored.b == looked_up.b
            }
        );
        // 3. does the lookup find it?
        assert_eq!(t.get(&looked_up, 10), Some(owner));
    }

    #[test]
    fn endpoint_order_does_not_change_the_hash() {
        let mut a = [0u8; 16];
        a[..4].copy_from_slice(&[10, 0, 0, 1]);
        let mut b = [0u8; 16];
        b[..4].copy_from_slice(&[1, 1, 1, 1]);
        let forward = FlowKey {
            a: Endpoint {
                addr: a,
                port: 51515,
            },
            b: Endpoint { addr: b, port: 443 },
            protocol: Protocol::Tcp,
            pid: 7,
        };
        let backward = FlowKey {
            a: forward.b,
            b: forward.a,
            ..forward
        };
        assert_eq!(
            FlowAttribution::slot_of_for_test(&forward),
            FlowAttribution::slot_of_for_test(&backward),
            "a reverse-ordered tuple must land in the same slot"
        );
        let mut t = FlowAttribution::new(64, 60_000);
        t.insert(forward, ProcKey::new(7, 0), 0);
        assert_eq!(t.get(&backward, 1), Some(ProcKey::new(7, 0)));
    }
}
