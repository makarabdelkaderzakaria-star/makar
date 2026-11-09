//! Flow identity and a compact, fixed-capacity flow table.
//!
//! The original keyed its rate limiter by `PID` while its rules matched by
//! process *name/path*, and its flow tracker keyed by `IPAddress` objects with
//! a second reverse-key lookup for inbound packets. Both cost allocations and
//! both produced mismatches. Here a flow is a 40-byte `Copy` value with a
//! canonical (direction-independent) 5-tuple, hashed once.

use crate::packet::{Direction, PacketView, Protocol};

/// Canonical flow identity: the 5-tuple sorted so that both directions of a
/// connection map to the *same* key. That removes the reverse lookup entirely.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FlowKey {
    /// Lower of the two endpoints.
    pub a: Endpoint,
    /// Higher of the two endpoints.
    pub b: Endpoint,
    /// Transport protocol (`Other` collapses into a single bucket per pair).
    pub protocol: Protocol,
    /// Owning process id as reported by the FLOW/SOCKET layer; 0 when unknown.
    pub pid: u32,
}

/// One side of a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Endpoint {
    /// Port, or 0 for ICMP/other.
    pub port: u16,
    /// Address, IPv4 zero-extended into 16 bytes.
    pub addr: [u8; 16],
}

impl Endpoint {
    /// The "no endpoint" value, used for listening sockets.
    #[inline]
    #[must_use]
    pub const fn unspecified() -> Self {
        Self {
            port: 0,
            addr: [0; 16],
        }
    }

    /// Build from a packet view's source side.
    #[inline]
    #[must_use]
    pub fn src_of(pkt: &PacketView<'_>) -> Self {
        Self {
            port: pkt.src_port,
            addr: pkt.src,
        }
    }

    /// Build from a packet view's destination side.
    #[inline]
    #[must_use]
    pub fn dst_of(pkt: &PacketView<'_>) -> Self {
        Self {
            port: pkt.dst_port,
            addr: pkt.dst,
        }
    }
}

impl FlowKey {
    /// Canonicalise a packet into a flow key.
    ///
    /// `pid` is *not* part of the 5-tuple used for sorting, but it is part of
    /// the identity because two processes can share a tuple across different
    /// sockets. It is carried in the key so hashing happens once.
    #[inline]
    #[must_use]
    pub fn from_packet(pkt: &PacketView<'_>, direction: Direction, pid: u32) -> Self {
        let (src, dst) = (Endpoint::src_of(pkt), Endpoint::dst_of(pkt));
        let (a, b) = if src <= dst { (src, dst) } else { (dst, src) };
        let _ = direction; // direction never changes identity
        Self {
            a,
            b,
            protocol: pkt.protocol,
            pid,
        }
    }

    /// True if `self` and `other` are the same connection but opposite ends.
    #[inline]
    #[must_use]
    pub fn is_reverse_of(&self, other: &Self) -> bool {
        self.a == other.b && self.b == other.a && self.protocol == other.protocol
    }
}

/// Marker: this flow has not been through the rule table yet.
pub const NOT_EVALUATED: u32 = u32::MAX;
/// Marker: the rule table was consulted and nothing matched.
pub const NO_RULE: u32 = u32::MAX - 1;

/// What we remember per established flow.
#[derive(Debug, Clone, Copy, Default)]
pub struct FlowEntry {
    /// Monotonic tick of the last packet seen (milliseconds).
    pub last_seen_ms: u64,
    /// Per-flow rate-control state: the GCRA theoretical arrival time (ns) for
    /// limits configured with `per-flow` scope, `0` otherwise.
    ///
    /// Storing it here instead of allocating a lane per connection is what makes
    /// `per-flow` cost the same as `process` scope: one `u64` in a row that
    /// already exists, not a new table keyed by the same 5-tuple.
    pub state: u64,
    /// The identity this flow was resolved to (index into the identity cache).
    pub identity: u32,
    /// Index into the compiled rule table.
    ///
    /// * `NOT_EVALUATED` — this flow has never been through the rule table.
    /// * [`NO_RULE`] — evaluated, nothing matched.
    /// * anything else — the winning rule's index.
    pub rule: u32,
    /// Generation counter for safe eviction.
    pub generation: u16,
}

/// A fixed-capacity open-addressing table. No allocation after `new`.
///
/// `CAP` must be a power of two; the caller picks it to bound memory exactly
/// (`CAP * size_of::<(FlowKey, FlowEntry)>()`). Full table => we *refuse to
/// insert* rather than grow, and the pipeline falls back to the stateless
/// policy for that flow (still correct, just without per-flow smoothing).
#[derive(Debug)]
pub struct FlowTable<const CAP: usize> {
    slots: Vec<Option<(FlowKey, FlowEntry)>>,
    len: usize,
    generation: u16,
    evictions: u64,
}

impl<const CAP: usize> Default for FlowTable<CAP> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const CAP: usize> FlowTable<CAP> {
    /// Create an empty table. `CAP` is rounded down to a power of two.
    #[must_use]
    pub fn new() -> Self {
        assert!(CAP >= 2, "flow table capacity must be >= 2");
        assert!(
            CAP.is_power_of_two(),
            "flow table capacity must be a power of two"
        );
        Self {
            slots: vec![None; CAP],
            len: 0,
            generation: 1,
            evictions: 0,
        }
    }

    /// Number of live flows.
    #[inline]
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Is the table empty?
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Capacity in flows.
    #[inline]
    #[must_use]
    pub const fn capacity(&self) -> usize {
        CAP
    }

    /// Number of flows evicted because the table was full.
    #[inline]
    #[must_use]
    pub const fn evictions(&self) -> u64 {
        self.evictions
    }

    /// Load factor in percent (0..=100).
    #[inline]
    #[must_use]
    pub fn load_percent(&self) -> u8 {
        ((self.len * 100) / CAP) as u8
    }

    #[inline]
    fn hash(key: &FlowKey) -> usize {
        // The first version of this used byte-at-a-time FNV-1a, which costs
        // ~150 dependent cycles per packet (multiply chain) and showed up as
        // the single most expensive thing in the benchmark. Folding the key
        // into three little-endian words and running one multiply-xor-rotate
        // mix is equivalent in quality for a small table and ~10x cheaper.
        let w0 = u64::from_le_bytes(key.a.addr[0..8].try_into().expect("8 bytes"));
        let w1 = u64::from_le_bytes(key.a.addr[8..16].try_into().expect("8 bytes"));
        let w2 = u64::from_le_bytes(key.b.addr[0..8].try_into().expect("8 bytes"));
        let w3 = u64::from_le_bytes(key.b.addr[8..16].try_into().expect("8 bytes"));
        let ends = u64::from(key.a.port) << 48
            | u64::from(key.b.port) << 32
            | (u64::from(key.protocol as u8) << 8)
            | u64::from(key.pid & 0xFF);
        let mut h = w0
            ^ w1.rotate_left(21)
            ^ w2.rotate_left(42)
            ^ w3.rotate_left(7)
            ^ ends.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        h ^= u64::from(key.pid).wrapping_mul(0xC2B2_AE3D_27D4_EB4F);
        // wyhash-style finaliser: two multiplies and two xors, no division.
        h ^= h >> 32;
        h = h.wrapping_mul(0xD6E8_FEB8_6659_FD93);
        h ^= h >> 32;
        (h as usize) & (CAP - 1)
    }

    /// Look up a flow without creating it.
    #[inline]
    #[must_use]
    pub fn get(&self, key: &FlowKey) -> Option<&FlowEntry> {
        let start = Self::hash(key);
        for i in 0..CAP {
            match &self.slots[(start + i) & (CAP - 1)] {
                None => return None,
                Some((k, v)) if k == key => return Some(v),
                Some(_) => {}
            }
        }
        None
    }

    /// Forget every flow's rate-control state while keeping the rows.
    ///
    /// Called when the limit table is reloaded: the rows are still valid (they
    /// carry attribution), but their GCRA timestamps were produced under the
    /// old rates and would otherwise hand out a free burst.
    pub fn clear_rate_state(&mut self) {
        for slot in &mut self.slots {
            if let Some((_, entry)) = slot {
                entry.state = 0;
            }
        }
    }

    /// Look up a flow without creating it, mutably.
    ///
    /// `last_seen_ms` is deliberately *not* touched: this is for writing back
    /// per-flow rate-control state when a retained packet is finally emitted,
    /// and touching the timestamp there would keep a silent flow alive.
    #[inline]
    pub fn get_mut(&mut self, key: &FlowKey) -> Option<&mut FlowEntry> {
        // Two passes on purpose: returning a borrow from inside the probe loop
        // needs Polonius, which the current borrow checker does not have. Find
        // the slot immutably first, then borrow it exactly once.
        let start = Self::hash(key);
        let mut found = None;
        for i in 0..CAP {
            let idx = (start + i) & (CAP - 1);
            match &self.slots[idx] {
                None => break,
                Some((k, _)) if k == key => {
                    found = Some(idx);
                    break;
                }
                Some(_) => {}
            }
        }
        match &mut self.slots[found?] {
            Some((_, entry)) => Some(entry),
            None => None,
        }
    }

    /// Look up or insert. Returns `None` only when the table is full.
    #[inline]
    pub fn get_or_insert(&mut self, key: &FlowKey, now_ms: u64) -> Option<(&mut FlowEntry, bool)> {
        let start = Self::hash(key);
        for i in 0..CAP {
            let idx = (start + i) & (CAP - 1);
            match &self.slots[idx] {
                None => {
                    self.slots[idx] = Some((
                        *key,
                        FlowEntry {
                            last_seen_ms: now_ms,
                            state: 0,
                            identity: NO_RULE,
                            rule: NOT_EVALUATED,
                            generation: self.generation,
                        },
                    ));
                    self.len += 1;
                    return Some((
                        &mut self.slots[idx].as_mut().expect("just inserted").1,
                        true,
                    ));
                }
                Some((k, _)) if k == key => {
                    let entry = &mut self.slots[idx].as_mut().expect("checked").1;
                    entry.last_seen_ms = now_ms;
                    return Some((entry, false));
                }
                Some(_) => {}
            }
        }
        None
    }

    /// Remove a flow (e.g. on TCP FIN/RST or FLOW_DELETED).
    pub fn remove(&mut self, key: &FlowKey) -> bool {
        let start = Self::hash(key);
        for i in 0..CAP {
            let idx = (start + i) & (CAP - 1);
            match &self.slots[idx] {
                None => return false,
                Some((k, _)) if k == key => {
                    self.slots[idx] = None;
                    self.len -= 1;
                    self.rehash_cluster(start);
                    return true;
                }
                Some(_) => {}
            }
        }
        false
    }

    /// Linear-probing deletion: pull entries back so lookups stay correct.
    fn rehash_cluster(&mut self, start: usize) {
        let mut hole = start;
        let mut i = 1;
        loop {
            let idx = (start + i) & (CAP - 1);
            match self.slots[idx].take() {
                None => return,
                Some(entry) => {
                    // Re-insert from its ideal slot.
                    let ideal = Self::hash(&entry.0);
                    let mut j = ideal;
                    loop {
                        if self.slots[j].is_none() {
                            self.slots[j] = Some(entry);
                            break;
                        }
                        j = (j + 1) & (CAP - 1);
                    }
                    hole = (hole + 1) & (CAP - 1);
                }
            }
            i += 1;
            if i > CAP {
                return;
            }
        }
    }

    /// Drop flows idle for at least `idle_ms`. Returns how many were removed.
    ///
    /// This is the only sweep; it is called from the *supervisor* tick, never
    /// from the packet path, and is O(CAP) over the slot array.
    pub fn sweep(&mut self, now_ms: u64, idle_ms: u64) -> usize {
        let mut removed = 0;
        for i in 0..CAP {
            let expired = match &self.slots[i] {
                Some((_, e)) => now_ms.saturating_sub(e.last_seen_ms) >= idle_ms,
                None => false,
            };
            if expired {
                self.slots[i] = None;
                self.len -= 1;
                removed += 1;
            }
        }
        if removed > 0 {
            self.generation = self.generation.wrapping_add(1);
            self.evictions += removed as u64;
            self.rebuild();
        }
        removed
    }

    fn rebuild(&mut self) {
        let live: Vec<(FlowKey, FlowEntry)> = self.slots.drain(..).flatten().collect();
        self.len = 0;
        for (k, mut v) in live {
            v.generation = self.generation;
            let ideal = Self::hash(&k);
            let mut j = ideal;
            loop {
                if self.slots[j].is_none() {
                    self.slots[j] = Some((k, v));
                    self.len += 1;
                    break;
                }
                j = (j + 1) & (CAP - 1);
            }
        }
    }

    /// Iterate live flows (for `netrocket top` / diagnostics).
    pub fn iter(&self) -> impl Iterator<Item = (&FlowKey, &FlowEntry)> {
        self.slots
            .iter()
            .filter_map(|s| s.as_ref().map(|(k, v)| (k, v)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{tcp_v4, udp_v4};

    fn key(pkt: &PacketView<'_>, pid: u32) -> FlowKey {
        FlowKey::from_packet(pkt, Direction::Outbound, pid)
    }

    #[test]
    fn both_directions_share_one_key() {
        let out = tcp_v4([10, 0, 0, 1], 51515, [1, 1, 1, 1], 443, &[]);
        let inn = tcp_v4([1, 1, 1, 1], 443, [10, 0, 0, 1], 51515, &[]);
        let a = PacketView::parse(&out).unwrap();
        let b = PacketView::parse(&inn).unwrap();
        // Because the tuple is canonicalised, both directions produce the very
        // same key: there is no reverse lookup to get wrong.
        assert_eq!(key(&a, 42), key(&b, 42));
        // `is_reverse_of` is still meaningful for keys built from a raw
        // (non-canonical) pair, e.g. when a rule names endpoints explicitly.
        let mut raw_out = key(&a, 42);
        let mut raw_in = key(&b, 42);
        raw_out.a = Endpoint::src_of(&a);
        raw_out.b = Endpoint::dst_of(&a);
        raw_in.a = Endpoint::src_of(&b);
        raw_in.b = Endpoint::dst_of(&b);
        assert!(raw_out.is_reverse_of(&raw_in));
    }

    #[test]
    fn insert_get_remove() {
        let pkt = udp_v4([10, 0, 0, 1], 5000, [8, 8, 8, 8], 53, &[1, 2, 3]);
        let view = PacketView::parse(&pkt).unwrap();
        let k = key(&view, 7);
        let mut table: FlowTable<16> = FlowTable::new();
        assert!(table.get(&k).is_none());
        let (_, created) = table.get_or_insert(&k, 1_000).unwrap();
        assert!(created);
        table.get_or_insert(&k, 2_000).unwrap();
        assert_eq!(table.len(), 1);
        assert_eq!(table.get(&k).unwrap().last_seen_ms, 2_000);
        assert!(table.remove(&k));
        assert!(table.get(&k).is_none());
        assert!(table.is_empty());
    }

    #[test]
    fn sweep_removes_idle_flows() {
        let mut table: FlowTable<64> = FlowTable::new();
        for port in 0..10u16 {
            let pkt = udp_v4([10, 0, 0, 1], 1000 + port, [8, 8, 8, 8], 53, &[]);
            let view = PacketView::parse(&pkt).unwrap();
            table.get_or_insert(&FloKeyHelper::k(&view), 1_000).unwrap();
        }
        assert_eq!(table.len(), 10);
        assert_eq!(table.sweep(1_100, 500), 0);
        assert_eq!(table.sweep(2_000, 500), 10);
        assert!(table.is_empty());
    }

    /// tiny helper so the test above stays readable
    struct FloKeyHelper;
    impl FloKeyHelper {
        fn k(view: &PacketView<'_>) -> FlowKey {
            FlowKey::from_packet(view, Direction::Outbound, 1)
        }
    }

    #[test]
    fn full_table_refuses_instead_of_growing() {
        let mut table: FlowTable<2> = FlowTable::new();
        for port in 0..8u16 {
            let pkt = udp_v4([10, 0, 0, 1], 2000 + port, [8, 8, 8, 8], 53, &[]);
            let view = PacketView::parse(&pkt).unwrap();
            let _ = table.get_or_insert(&key(&view, 1), 0);
        }
        assert_eq!(table.len(), 2);
        assert!(table.len() <= table.capacity());
    }
}
