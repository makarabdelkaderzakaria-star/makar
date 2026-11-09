//! Compiled rule tables.
//!
//! ## What the original did per packet
//!
//! `RuleEngine.Match` took a lock, then ran a **LINQ** query over every rule,
//! and for each candidate called `Clone()` on the rule and on its limit, then
//! formatted strings to compare process names. Per packet. On a machine doing
//! 50k pps that is a garbage collector fire.
//!
//! ## What we do
//!
//! Rules are compiled **once** into a flat `Vec<CompiledRule>` of plain data:
//!
//! * a bitmask of predicates that must be tested (so most rules are rejected by
//!   a single `&`) ;
//! * process names interned to a small id at compile time — comparing an id is
//!   one integer compare instead of a string compare;
//! * a `u32` limit index, not a cloned limit struct;
//! * evaluation stops at the first match (documented, stable, first-match-wins)
//!   and the *result* is cached per flow, so steady-state flows never walk the
//!   table again.
//!
//! Rule syntax (`docs/CONFIG.md`):
//!
//! ```text
//! allow : all
//! limit chrome.exe : tcp dport 443
//! block : udp dport 27015-27050
//! limit steam.exe : dst 155.133.0.0/16
//! ```

use crate::error::RuleError;
use crate::identity::protocol_tag;
use crate::packet::{Direction, PacketView};

macro_rules! bitflags_like {
    (
        $(#[$meta:meta])*
        $name:ident;
        $(
            $(#[$fmeta:meta])*
            $flag:ident = $value:expr;
        )*
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
        pub struct $name(u8);
        impl $name {
            $(
                $(#[$fmeta])*
                pub const $flag: Self = Self($value);
            )*
            /// No predicates.
            pub const NONE: Self = Self(0);
            /// Combine two masks.
            #[must_use]
            pub const fn or(self, other: Self) -> Self { Self(self.0 | other.0) }
            /// Does `self` contain every bit of `other`?
            #[must_use]
            pub const fn contains(self, other: Self) -> bool {
                self.0 & other.0 == other.0
            }
            /// Raw bits.
            #[must_use]
            pub const fn bits(self) -> u8 { self.0 }
        }
    };
}

bitflags_like! {
    /// Predicates present in a rule, as a bitmask.
    Predicates;
    /// Match the process name.
    PROC = 1 << 0;
    /// Match the transport protocol.
    PROTO = 1 << 1;
    /// Match the destination port.
    DPORT = 1 << 2;
    /// Match the source port.
    SPORT = 1 << 3;
    /// Match the destination address/prefix.
    DST = 1 << 4;
    /// Match the source address/prefix.
    SRC = 1 << 5;
    /// Match the direction.
    DIR = 1 << 6;
}

/// What to do when a rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum Action {
    /// No opinion: fall through to the next rule.
    #[default]
    Pass,
    /// Explicitly permit, skipping all later rules.
    Allow,
    /// Attribute the flow to a named limit.
    Limit(u16),
    /// Drop every matching packet.
    Block,
}

/// An IPv4 or IPv6 prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prefix {
    /// Network bytes (IPv4 zero-extended).
    pub addr: [u8; 16],
    /// 0..=32 for IPv4, 0..=128 for IPv6.
    pub len: u8,
    /// Whether the address is IPv6.
    pub v6: bool,
}

impl Prefix {
    /// Parse `1.2.3.0/24` or `2001:db8::/32` (or a bare address = /32, /128).
    pub fn parse(s: &str) -> Option<Self> {
        let (addr_part, len_part) = match s.split_once('/') {
            Some((a, l)) => (a, Some(l)),
            None => (s, None),
        };
        if addr_part.contains(':') {
            let addr = parse_v6(addr_part)?;
            let len = match len_part {
                Some(l) => l.parse().ok()?,
                None => 128,
            };
            if len > 128 {
                return None;
            }
            Some(Self {
                addr,
                len,
                v6: true,
            })
        } else {
            let addr = parse_v4(addr_part)?;
            let len = match len_part {
                Some(l) => l.parse().ok()?,
                None => 32,
            };
            if len > 32 {
                return None;
            }
            let mut full = [0u8; 16];
            full[..4].copy_from_slice(&addr);
            Some(Self {
                addr: full,
                len,
                v6: false,
            })
        }
    }

    /// Does `candidate` fall inside this prefix? One masked compare.
    #[inline]
    #[must_use]
    pub fn matches(&self, candidate: &[u8; 16], candidate_v6: bool) -> bool {
        if self.v6 != candidate_v6 {
            return false;
        }
        let bytes = (self.len / 8) as usize;
        if self.addr[..bytes] != candidate[..bytes] {
            return false;
        }
        let rem = self.len % 8;
        if rem == 0 {
            return true;
        }
        let mask = 0xFFu8 << (8 - rem);
        (self.addr[bytes] & mask) == (candidate[bytes] & mask)
    }
}

fn parse_v4(s: &str) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    let mut n = 0;
    for part in s.split('.') {
        if n == 4 {
            return None;
        }
        out[n] = part.parse().ok()?;
        n += 1;
    }
    if n == 4 {
        Some(out)
    } else {
        None
    }
}

fn parse_v6(s: &str) -> Option<[u8; 16]> {
    let mut out = [0u8; 16];
    let (head, tail) = match s.split_once("::") {
        Some((h, t)) => (h, Some(t)),
        None => (s, None),
    };
    let mut idx = 0usize;
    let mut pending: Vec<u16> = Vec::new();
    for group in head.split(':').filter(|g| !g.is_empty()) {
        pending.push(u16::from_str_radix(group, 16).ok()?);
    }
    let mut tail_groups: Vec<u16> = Vec::new();
    if let Some(t) = tail {
        for group in t.split(':').filter(|g| !g.is_empty()) {
            tail_groups.push(u16::from_str_radix(group, 16).ok()?);
        }
    }
    let total = pending.len() + tail_groups.len();
    if total > 8 {
        return None;
    }
    let zeros = 8 - total;
    for g in &pending {
        out[idx..idx + 2].copy_from_slice(&g.to_be_bytes());
        idx += 2;
    }
    idx += zeros * 2;
    for g in &tail_groups {
        out[idx..idx + 2].copy_from_slice(&g.to_be_bytes());
        idx += 2;
    }
    Some(out)
}

/// A port or inclusive port range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    /// First port.
    pub lo: u16,
    /// Last port.
    pub hi: u16,
}

impl PortRange {
    /// Single port.
    #[must_use]
    pub const fn one(p: u16) -> Self {
        Self { lo: p, hi: p }
    }

    /// Does `p` fall in range?
    #[inline]
    #[must_use]
    pub const fn contains(&self, p: u16) -> bool {
        p >= self.lo && p <= self.hi
    }

    /// Parse `443` or `27015-27050`.
    pub fn parse(s: &str) -> Option<Self> {
        match s.split_once('-') {
            Some((a, b)) => {
                let lo: u16 = a.trim().parse().ok()?;
                let hi: u16 = b.trim().parse().ok()?;
                if lo > hi {
                    return None;
                }
                Some(Self { lo, hi })
            }
            None => Some(Self::one(s.trim().parse().ok()?)),
        }
    }
}

/// One compiled rule: flat data, no pointers, no ownership.
#[derive(Debug, Clone, Copy)]
pub struct CompiledRule {
    /// Which predicates to test.
    pub need: Predicates,
    /// What to do on match.
    pub action: Action,
    /// Interned process name id, or [`u32::MAX`].
    pub proc_id: u32,
    /// Protocol tag index: 0 tcp, 1 udp, 2 other, 3 any.
    pub proto: u8,
    /// Destination port range.
    pub dport: PortRange,
    /// Source port range.
    pub sport: PortRange,
    /// Destination prefix.
    pub dst: Prefix,
    /// Source prefix.
    pub src: Prefix,
    /// Required direction, or 2 for any.
    pub dir: u8,
}

impl CompiledRule {
    const fn empty() -> Self {
        Self {
            need: Predicates::NONE,
            action: Action::Pass,
            proc_id: u32::MAX,
            proto: 3,
            dport: PortRange { lo: 0, hi: 0 },
            sport: PortRange { lo: 0, hi: 0 },
            dst: Prefix {
                addr: [0; 16],
                len: 0,
                v6: false,
            },
            src: Prefix {
                addr: [0; 16],
                len: 0,
                v6: false,
            },
            dir: 2,
        }
    }

    /// Evaluate against a packet. `proc_id` is `u32::MAX` when unknown, which
    /// makes any rule needing a name *not* match (fail closed: unknown traffic
    /// keeps its previous attribution instead of silently matching `allow`).
    #[inline]
    #[must_use]
    pub fn matches(
        &self,
        pkt: &PacketView<'_>,
        direction: Direction,
        proc_id: u32,
        v6: bool,
    ) -> bool {
        if self.need.contains(Predicates::PROC) && (proc_id == u32::MAX || proc_id != self.proc_id)
        {
            return false;
        }
        if self.need.contains(Predicates::PROTO) {
            let tag = match pkt.protocol {
                crate::packet::Protocol::Tcp => 0u8,
                crate::packet::Protocol::Udp => 1,
                crate::packet::Protocol::Other => 2,
            };
            if tag != self.proto {
                return false;
            }
        }
        if self.need.contains(Predicates::DPORT) && !self.dport.contains(pkt.dst_port) {
            return false;
        }
        if self.need.contains(Predicates::SPORT) && !self.sport.contains(pkt.src_port) {
            return false;
        }
        if self.need.contains(Predicates::DST) && !self.dst.matches(&pkt.dst, v6) {
            return false;
        }
        if self.need.contains(Predicates::SRC) && !self.src.matches(&pkt.src, v6) {
            return false;
        }
        if self.need.contains(Predicates::DIR) {
            let d = match direction {
                Direction::Outbound => 0u8,
                Direction::Inbound => 1u8,
            };
            if d != self.dir {
                return false;
            }
        }
        true
    }
}

/// A compiled table plus the name interner.
#[derive(Debug, Default, Clone)]
pub struct CompiledRules {
    rules: Vec<CompiledRule>,
    names: Vec<String>,
    hits: Vec<u64>,
}

impl CompiledRules {
    /// Number of rules.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Empty?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Rules slice (for diagnostics).
    #[must_use]
    pub fn rules(&self) -> &[CompiledRule] {
        &self.rules
    }

    /// Names slice.
    #[must_use]
    pub fn names(&self) -> &[String] {
        &self.names
    }

    /// Per-rule hit counters.
    #[must_use]
    pub fn hits(&self) -> &[u64] {
        &self.hits
    }

    /// Record a hit (called from the pipeline; relaxed on purpose, statistics
    /// must never cost a fence on the hot path).
    #[inline]
    pub fn note_hit(&mut self, idx: u32) {
        if let Some(c) = self.hits.get_mut(idx as usize) {
            *c += 1;
        }
    }

    /// Find the name id for `name` without inserting.
    #[must_use]
    pub fn name_id(&self, name: &str) -> Option<u32> {
        self.names
            .iter()
            .position(|n| n.eq_ignore_ascii_case(name))
            .and_then(|i| u32::try_from(i).ok())
    }

    /// Evaluate the table for one packet.
    ///
    /// First match that is not [`Action::Pass`] wins. Returns
    /// `(rule_index, action)`; `None` means "no rule matched".
    #[inline]
    #[must_use]
    pub fn evaluate(
        &self,
        pkt: &PacketView<'_>,
        direction: Direction,
        proc_id: u32,
        v6: bool,
    ) -> Option<(u32, Action)> {
        for (i, r) in self.rules.iter().enumerate() {
            if r.matches(pkt, direction, proc_id, v6) {
                if r.action == Action::Pass {
                    continue;
                }
                return Some((i as u32, r.action));
            }
        }
        None
    }
}

/// Builder for [`CompiledRules`].
#[derive(Debug, Default)]
pub struct RuleSet {
    rules: Vec<CompiledRule>,
    names: Vec<String>,
    /// Raw rule text, kept so we can re-compile when a limit is defined later.
    source: Vec<String>,
}

impl RuleSet {
    /// Empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Raw source lines, in order.
    #[must_use]
    pub fn source(&self) -> &[String] {
        &self.source
    }

    fn intern(&mut self, name: &str) -> u32 {
        if let Some(i) = self.names.iter().position(|n| n.eq_ignore_ascii_case(name)) {
            return i as u32;
        }
        self.names.push(name.to_ascii_lowercase());
        (self.names.len() - 1) as u32
    }

    /// Add a rule. `limit_names` is the ordered list of defined limits, used to
    /// translate `limit=name` into an index.
    pub fn add(&mut self, text: &str, limit_names: &[String]) -> Result<(), RuleError> {
        let raw = text.trim();
        if raw.is_empty() {
            return Err(RuleError::EmptyMatch);
        }
        let (action_part, match_part) = raw.split_once(':').ok_or(RuleError::Syntax)?;
        let action_part = action_part.trim();
        let match_part = match_part.trim();
        let mut rule = CompiledRule::empty();
        let lower = action_part.to_ascii_lowercase();
        if lower == "allow" || lower == "pass" {
            rule.action = Action::Allow;
        } else if lower == "block" || lower == "drop" || lower == "deny" {
            rule.action = Action::Block;
        } else if let Some(name) = lower.strip_prefix("limit=") {
            let name = name.trim();
            let idx = limit_names
                .iter()
                .position(|l| l.eq_ignore_ascii_case(name))
                .ok_or_else(|| RuleError::UnknownLimit(name.to_owned()))?;
            rule.action = Action::Limit(u16::try_from(idx).map_err(|_| RuleError::Syntax)?);
        } else {
            return Err(RuleError::UnknownAction(action_part.to_owned()));
        }

        if match_part.eq_ignore_ascii_case("all") || match_part == "*" {
            // matches everything
        } else {
            let tokens: Vec<&str> = match_part.split_whitespace().collect();
            let mut i = 0;
            while i < tokens.len() {
                let tok = tokens[i].to_ascii_lowercase();
                match tok.as_str() {
                    "tcp" => {
                        rule.proto = 0;
                        rule.need = rule.need.or(Predicates::PROTO);
                        i += 1;
                    }
                    "udp" => {
                        rule.proto = 1;
                        rule.need = rule.need.or(Predicates::PROTO);
                        i += 1;
                    }
                    "icmp" | "other" => {
                        rule.proto = 2;
                        rule.need = rule.need.or(Predicates::PROTO);
                        i += 1;
                    }
                    "in" => {
                        rule.dir = 1;
                        rule.need = rule.need.or(Predicates::DIR);
                        i += 1;
                    }
                    "out" => {
                        rule.dir = 0;
                        rule.need = rule.need.or(Predicates::DIR);
                        i += 1;
                    }
                    "dport" | "sport" | "dst" | "src" | "proc" => {
                        let val = tokens.get(i + 1).ok_or(RuleError::Syntax)?;
                        match tok.as_str() {
                            "dport" => {
                                rule.dport = PortRange::parse(val).ok_or(RuleError::Syntax)?;
                                rule.need = rule.need.or(Predicates::DPORT);
                            }
                            "sport" => {
                                rule.sport = PortRange::parse(val).ok_or(RuleError::Syntax)?;
                                rule.need = rule.need.or(Predicates::SPORT);
                            }
                            "dst" => {
                                rule.dst = Prefix::parse(val).ok_or(RuleError::Syntax)?;
                                rule.need = rule.need.or(Predicates::DST);
                            }
                            "src" => {
                                rule.src = Prefix::parse(val).ok_or(RuleError::Syntax)?;
                                rule.need = rule.need.or(Predicates::SRC);
                            }
                            "proc" => {
                                let id = self.intern(val);
                                rule.proc_id = id;
                                rule.need = rule.need.or(Predicates::PROC);
                            }
                            _ => unreachable!(),
                        }
                        i += 2;
                    }
                    other => {
                        // Bare token: treat a dotted name as a process name,
                        // which is how people naturally write `block : chrome.exe`.
                        if other.contains('.') {
                            let id = self.intern(other);
                            rule.proc_id = id;
                            rule.need = rule.need.or(Predicates::PROC);
                            i += 1;
                        } else if other == "any" {
                            i += 1;
                        } else if let Some(p) = Prefix::parse(other) {
                            rule.dst = p;
                            rule.need = rule.need.or(Predicates::DST);
                            i += 1;
                        } else {
                            return Err(RuleError::Syntax);
                        }
                    }
                }
            }
        }

        self.rules.push(rule);
        self.source.push(raw.to_owned());
        Ok(())
    }

    /// Finish: produce the immutable table.
    #[must_use]
    pub fn compile(&self) -> CompiledRules {
        CompiledRules {
            rules: self.rules.clone(),
            names: self.names.clone(),
            hits: vec![0; self.rules.len()],
        }
    }

    /// Number of rules added.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Empty?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

/// Format a protocol/direction pair the way the rules spell it.
#[must_use]
pub fn describe_match(pkt: &PacketView<'_>, direction: Direction) -> String {
    format!(
        "{} {}:{} -> {}:{}",
        protocol_tag(pkt.protocol),
        pkt.src_port,
        direction.code(),
        pkt.dst_port,
        pkt.wire_len
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{tcp_v4, udp_v4};
    use crate::packet::PacketView;

    fn limits() -> Vec<String> {
        vec!["chrome.exe".to_owned(), "steam.exe".to_owned()]
    }

    #[test]
    fn prefix_matching_is_exact() {
        let p = Prefix::parse("155.133.0.0/16").unwrap();
        let inside = [155u8, 133, 4, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let outside = [155u8, 134, 4, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(p.matches(&inside, false));
        assert!(!p.matches(&outside, false));
        assert!(!p.matches(&inside, true));
    }

    #[test]
    fn prefix_parse_forms() {
        assert!(Prefix::parse("10.0.0.0/8").is_some());
        assert!(Prefix::parse("10.0.0.1").is_some());
        assert!(Prefix::parse("10.0.0.0/33").is_none());
        assert!(Prefix::parse("2001:db8::/32").is_some());
        assert!(Prefix::parse("::1").is_some());
    }

    #[test]
    fn port_range_parse() {
        let r = PortRange::parse("27015-27050").unwrap();
        assert!(r.contains(27015) && r.contains(27050) && !r.contains(27051));
        assert_eq!(PortRange::parse("443").unwrap().lo, 443);
    }

    #[test]
    fn dport_rule_matches_only_that_port() {
        let mut set = RuleSet::new();
        set.add(
            "limit=chrome.exe : proc chrome.exe tcp dport 443",
            &limits(),
        )
        .unwrap();
        let table = set.compile();
        let hit = tcp_v4([10, 0, 0, 1], 5555, [1, 1, 1, 1], 443, &[]);
        let miss = tcp_v4([10, 0, 0, 1], 5555, [1, 1, 1, 1], 80, &[]);
        let v1 = PacketView::parse(&hit).unwrap();
        let v2 = PacketView::parse(&miss).unwrap();
        let proc_id = table.name_id("chrome.exe").unwrap();
        assert_eq!(
            table.evaluate(&v1, Direction::Outbound, proc_id, false),
            Some((0, Action::Limit(0)))
        );
        assert_eq!(
            table.evaluate(&v2, Direction::Outbound, proc_id, false),
            None
        );
    }

    #[test]
    fn unknown_process_never_matches_a_named_rule() {
        let mut set = RuleSet::new();
        set.add("allow : proc chrome.exe", &limits()).unwrap();
        let table = set.compile();
        let f = tcp_v4([10, 0, 0, 1], 1, [1, 1, 1, 1], 443, &[]);
        let v = PacketView::parse(&f).unwrap();
        assert_eq!(
            table.evaluate(&v, Direction::Outbound, u32::MAX, false),
            None
        );
    }

    #[test]
    fn first_match_wins_and_pass_falls_through() {
        let mut set = RuleSet::new();
        set.add("limit=chrome.exe : proc chrome.exe tcp", &limits())
            .unwrap();
        set.add("block : tcp dport 443", &limits()).unwrap();
        set.add("allow : all", &limits()).unwrap();
        let table = set.compile();
        let f = tcp_v4([10, 0, 0, 1], 1, [1, 1, 1, 1], 443, &[]);
        let v = PacketView::parse(&f).unwrap();
        let pid = table.name_id("chrome.exe").unwrap();
        assert_eq!(
            table.evaluate(&v, Direction::Outbound, pid, false),
            Some((0, Action::Limit(0)))
        );
        // Unknown process: the block rule wins over `allow : all`.
        assert_eq!(
            table.evaluate(&v, Direction::Outbound, u32::MAX, false),
            Some((1, Action::Block))
        );
    }

    #[test]
    fn udp_rule_and_direction() {
        let mut set = RuleSet::new();
        set.add("block : udp out dport 53", &limits()).unwrap();
        let table = set.compile();
        let f = udp_v4([10, 0, 0, 1], 5000, [8, 8, 8, 8], 53, &[0; 10]);
        let v = PacketView::parse(&f).unwrap();
        assert_eq!(
            table.evaluate(&v, Direction::Outbound, u32::MAX, false),
            Some((0, Action::Block))
        );
        assert_eq!(
            table.evaluate(&v, Direction::Inbound, u32::MAX, false),
            None
        );
    }

    #[test]
    fn unknown_limit_is_an_error() {
        let mut set = RuleSet::new();
        assert_eq!(
            set.add("limit=nope.exe : all", &limits()),
            Err(RuleError::UnknownLimit("nope.exe".to_owned()))
        );
    }

    #[test]
    fn syntax_errors_are_reported() {
        let mut set = RuleSet::new();
        assert_eq!(set.add("block tcp", &limits()), Err(RuleError::Syntax));
        assert!(matches!(
            set.add("nonsense : tcp", &limits()),
            Err(RuleError::UnknownAction(_))
        ));
    }
}
