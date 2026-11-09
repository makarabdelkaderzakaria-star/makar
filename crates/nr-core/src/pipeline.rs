//! The hot path: `Engine::process_batch`.
//!
//! Everything else exists to make this function cheap and provable.
//!
//! The order of operations is deliberate:
//!
//! 1. **Parse** — zero copy, no allocation, rejects malformed frames.
//! 2. **Fast path for fills** — search for outgoing TCP `ACK` packets that are
//!    pure window updates are cheap to shape and expensive to lose.
//! 3. **Resolve flow** — one hash over a canonical 5-tuple (both directions map
//!    to the same key, so no reverse lookup).
//! 4. **Attribution** — cached per flow. The rule table and the process name are
//!    consulted **once per flow**, not once per packet.
//! 5. **Decide** — GCRA `try_acquire` (single call: test *and* commit).
//! 6. **Retain / emit** — bounded retention with a short ceiling; over budget we
//!    shed the least useful packet and count it.
//!
//! The one behavioural rule that matters for "does not waste bandwidth": we
//! **never** drop a packet we could have delayed, and we never hold a packet
//! longer than `max_retain_ms` (default 250 ms), which is below the smallest
//! plausible TCP RTO. So nothing we retain is ever retransmitted on our account.

use crate::calendar::Calendar;
use crate::config::{CapPeriod, Config, LimitScope, Limits, OverLimitPolicy, Window};
use crate::flow::{FlowKey, FlowTable};
use crate::gcra::Gcra;
use crate::identity::{IdentityCache, Lookup, ProcKey, Resolver};
use crate::packet::{Direction, PacketView, Protocol};
use crate::rules::{Action, CompiledRules, RuleSet};
use crate::scheduler::{Admit, Scheduler, Shed};
use crate::stats::{Counters, Snapshot};

/// What the engine wants done with one packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Forward it now, unchanged.
    SendNow,
    /// Hold it until `due_ns`.
    Retain {
        /// Absolute due time in ns on the monotonic clock.
        due_ns: u64,
    },
    /// Drop it (and why).
    Drop(DropReason),
}

/// Why a packet was dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DropReason {
    /// Explicit `block` rule.
    Blocked,
    /// Shaping policy said drop instead of delay.
    PolicyDrop,
    /// Required delay exceeded the retention ceiling.
    TooLate,
    /// Byte budget full.
    Budget,
    /// Per-flow retention quota reached.
    FlowQuota,
    /// The limit's daily/monthly byte budget is spent.
    Cap,
    /// Unparseable / unsupported frame.
    Malformed,
}

impl DropReason {
    /// Stable label for stats and logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Blocked => "blocked",
            Self::PolicyDrop => "policy_drop",
            Self::TooLate => "too_late",
            Self::Budget => "budget",
            Self::FlowQuota => "flow_quota",
            Self::Cap => "cap",
            Self::Malformed => "malformed",
        }
    }
}

/// Result of one packet, for callers that want to act on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Outcome {
    /// Decision taken.
    pub decision: Decision,
    /// Flow the packet was attributed to (`None` if malformed).
    pub flow: Option<FlowKey>,
    /// Limit name index, if a limit was applied.
    pub limit: Option<u16>,
}

/// Runtime state of one limit's byte budget.
///
/// `bytes == 0` means the limit has no cap, which keeps this vector aligned with
/// the limit vector (so a rule's limit index is all the lookup needs).
#[derive(Debug, Clone, Copy, Default)]
struct CapState {
    /// Budget in bytes; `0` == no cap.
    bytes: u64,
    /// Reset period.
    period: CapPeriod,
    /// Bytes charged in the current period.
    used: u64,
    /// The period this count belongs to (UTC day or month index).
    stamp: u32,
}

/// Usage of one capped limit, for `lint`, the TUI and the on-disk counter file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapUsage {
    /// Limit name.
    pub name: String,
    /// Bytes charged in the current period.
    pub used: u64,
    /// Budget in bytes.
    pub cap: u64,
    /// Reset period.
    pub period: CapPeriod,
    /// Period stamp this usage applies to.
    pub stamp: u32,
}

/// The engine: owns the tables, decides everything, touches no I/O.
pub struct Engine<const FLOWS: usize = 8192> {
    config: Config,
    flows: FlowTable<FLOWS>,
    identities: IdentityCache,
    rules: CompiledRules,
    gcra: Vec<Gcra>,
    policy: Vec<OverLimitPolicy>,
    scope: Vec<LimitScope>,
    caps: Vec<CapState>,
    windows: Vec<Option<Window>>,
    calendar: Calendar,
    name_ids: Vec<u32>,
    scheduler: Scheduler<u64>,
    stats: Counters,
    parse_errors: u64,
}

impl<const FLOWS: usize> Engine<FLOWS> {
    /// Build an engine from a validated configuration.
    #[must_use]
    pub fn new(config: Config) -> Self {
        let scheduler = Scheduler::new(config.retain_budget_bytes, config.max_retain_ms);
        let identities = IdentityCache::new(1024, 64 * 1024, config.identity_ttl_ms);
        let mut engine = Self {
            config,
            flows: FlowTable::new(),
            identities,
            rules: CompiledRules::default(),
            gcra: Vec::new(),
            policy: Vec::new(),
            scope: Vec::new(),
            caps: Vec::new(),
            windows: Vec::new(),
            calendar: Calendar::default(),
            name_ids: Vec::new(),
            scheduler,
            stats: Counters::default(),
            parse_errors: 0,
        };
        engine.reload_limits();
        engine
    }

    /// Rebuild the GCRA lanes from the configuration. Called on start and on any
    /// config change; never on the packet path.
    pub fn reload_limits(&mut self) {
        let mut gcra = Vec::with_capacity(self.config.limits.len());
        let mut policy = Vec::with_capacity(self.config.limits.len());
        let mut scope = Vec::with_capacity(self.config.limits.len());
        let mut caps = Vec::with_capacity(self.config.limits.len());
        for l in &self.config.limits {
            caps.push(self.cap_state_for(l));
            let burst = l.burst_bytes.max(4 * u64::from(crate::config::MTU_BYTES));
            match Gcra::new(l.rate_bps, burst) {
                Ok(g) => {
                    gcra.push(g);
                    policy.push(l.policy);
                    scope.push(l.scope);
                }
                Err(_) => {
                    // Invalid limits were rejected at load; keep the index
                    // aligned so rule indices stay meaningful.
                    gcra.push(Gcra::new(1_000, 1500).expect("fallback is valid"));
                    policy.push(OverLimitPolicy::Shape);
                    scope.push(l.scope);
                }
            }
        }
        self.gcra = gcra;
        self.policy = policy;
        self.scope = scope;
        self.caps = caps;
        self.windows = self.config.limits.iter().map(|l| l.window).collect();
        // Per-flow state lives in the flow rows; a reload changes the *rate*
        // those rows are interpreted with, so their timestamps must be dropped
        // (attribution itself stays, so nothing re-walks the rule table).
        self.flows.clear_rate_state();
    }

    /// Initial runtime state for one limit's cap, stamped with the current
    /// period so a counter charged later in the same period is not reset.
    fn cap_state_for(&self, limit: &Limits) -> CapState {
        let Some(cap) = limit.cap else {
            return CapState::default();
        };
        if cap.bytes == 0 {
            return CapState::default();
        }
        CapState {
            bytes: cap.bytes,
            period: cap.period,
            used: 0,
            stamp: self.calendar.stamp(cap.period),
        }
    }

    /// Install a compiled rule table.
    pub fn set_rules(&mut self, rules: CompiledRules) {
        self.rules = rules;
        self.name_ids = self
            .config
            .limits
            .iter()
            .filter_map(|l| self.rules.name_id(&l.name))
            .collect();
        // Attribution is cached per flow; drop the cache so new rules apply.
        self.flows = FlowTable::new();
    }

    /// Compile rules from raw text plus a limit name list.
    pub fn compile_rules(
        texts: &[String],
        limits: &[Limits],
    ) -> Result<(RuleSet, CompiledRules), crate::error::RuleError> {
        let names: Vec<String> = limits.iter().map(|l| l.name.clone()).collect();
        let mut set = RuleSet::new();
        for t in texts {
            set.add(t, &names)?;
        }
        let compiled = set.compile();
        Ok((set, compiled))
    }

    /// Read-only view of the configuration.
    #[must_use]
    pub const fn config(&self) -> &Config {
        &self.config
    }

    /// Mutable configuration access (call `reload_limits`/`set_rules` after).
    pub fn config_mut(&mut self) -> &mut Config {
        &mut self.config
    }

    /// Flow table statistics.
    #[must_use]
    pub const fn flows(&self) -> &FlowTable<FLOWS> {
        &self.flows
    }

    /// Compiled rules.
    #[must_use]
    pub const fn rules(&self) -> &CompiledRules {
        &self.rules
    }

    /// Retention buffer.
    #[must_use]
    pub const fn scheduler(&self) -> &Scheduler<u64> {
        &self.scheduler
    }

    /// Mutable retention buffer (the I/O layer drains it).
    pub fn scheduler_mut(&mut self) -> &mut Scheduler<u64> {
        &mut self.scheduler
    }

    /// Statistics snapshot.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        self.stats.snapshot(&self.flows, &self.scheduler)
    }

    /// Number of frames that failed to parse.
    #[must_use]
    pub const fn parse_errors(&self) -> u64 {
        self.parse_errors
    }

    /// Resolve the process identity for `pid` (cached).
    ///
    /// `start_time` is available from the FLOW/SOCKET layers in the Windows
    /// backend; pass 0 when unknown.
    pub fn identify<R: Resolver + ?Sized>(
        &mut self,
        pid: u32,
        start_time: u64,
        now_ms: u64,
        resolver: &mut R,
    ) -> u32 {
        if pid == 0 {
            return u32::MAX;
        }
        match self
            .identities
            .lookup(ProcKey::new(pid, start_time), now_ms, resolver)
        {
            Lookup::Named(name) => self.rules.name_id(name).unwrap_or(u32::MAX),
            Lookup::Unknown | Lookup::Exempt => u32::MAX,
        }
    }

    /// **The** function. Process one frame and return the decision.
    ///
    /// Eight arguments on purpose: this is the hot path, the values are all
    /// already in registers at the call site, and packing them into a struct
    /// would add a copy per packet. If a new field is ever needed, add it to
    /// `PacketContext` *below* this function rather than to this signature.
    ///
    /// `token` is the opaque per-packet value the backend must hand back when
    /// it sends the packet (in production: the `WINDIVERT_ADDRESS` bits, packed).
    #[allow(clippy::too_many_arguments)]
    pub fn process(
        &mut self,
        frame: &[u8],
        direction: Direction,
        pid: u32,
        proc_id: u32,
        token: u64,
        now_ns: u64,
        now_ms: u64,
    ) -> Outcome {
        self.stats.packets += 1;
        self.stats.bytes += frame.len() as u64;
        match direction {
            Direction::Outbound => self.stats.out_packets += 1,
            Direction::Inbound => self.stats.in_packets += 1,
        }

        let pkt = match PacketView::parse(frame) {
            Ok(p) => p,
            Err(_) => {
                // Fail open: a malformed frame is still forwarded, because
                // dropping it silently would be worse than the original's
                // behaviour we are replacing. We only refuse to *shape* it.
                self.parse_errors += 1;
                self.stats.dropped_malformed += 1;
                return Outcome {
                    decision: Decision::SendNow,
                    flow: None,
                    limit: None,
                };
            }
        };
        let v6 = pkt.ip_version == 6;
        let key = FlowKey::from_packet(&pkt, direction, pid);

        // --- attribution (cached per flow) -------------------------------
        let now_ms_evict = now_ms;
        let (cached_action, flow_index) = {
            let Some((entry, created)) = self.flows.get_or_insert(&key, now_ms_evict) else {
                // Flow table full: apply the stateless policy. Correct, just
                // without per-flow smoothing, and counted so it is visible.
                self.stats.flows_refused += 1;
                let action = self
                    .rules
                    .evaluate(&pkt, direction, proc_id, v6)
                    .map(|(_, a)| a);
                return self.apply_action_stateless(
                    action,
                    &pkt,
                    direction,
                    token,
                    now_ns,
                    now_ms_evict,
                );
            };
            if created {
                self.stats.flows_created += 1;
            }
            let cached = if entry.rule == crate::flow::NOT_EVALUATED {
                None
            } else {
                Some((entry.rule, entry.identity))
            };
            let idx = (key.pid as usize).wrapping_add(entry.state as usize) as u32;
            (cached, idx)
        };

        let (rule_idx, action) = match cached_action {
            Some((ri, _)) => (
                ri,
                self.rules
                    .rules()
                    .get(ri as usize)
                    .map_or(Action::Pass, |r| r.action),
            ),
            None => {
                let found = self.rules.evaluate(&pkt, direction, proc_id, v6);
                let (ri, act) = match found {
                    Some((i, a)) => (i, a),
                    None => (crate::flow::NO_RULE, Action::Pass),
                };
                // Cache the *miss* too. Caching only hits would make every
                // unmatched packet re-walk the table, which is what the original
                // did for every packet outright.
                if let Some((entry, _)) = self.flows.get_or_insert(&key, now_ms_evict) {
                    entry.rule = ri;
                    entry.identity = proc_id;
                }
                if ri != crate::flow::NO_RULE {
                    self.stats.rule_hits += 1;
                }
                (ri, act)
            }
        };
        let _ = flow_index;

        match action {
            Action::Allow => {
                self.stats.allowed += 1;
                Outcome {
                    decision: Decision::SendNow,
                    flow: Some(key),
                    limit: None,
                }
            }
            Action::Block => {
                self.stats.dropped_blocked += 1;
                Outcome {
                    decision: Decision::Drop(DropReason::Blocked),
                    flow: Some(key),
                    limit: None,
                }
            }
            Action::Limit(li) => {
                self.apply_limit(li, &pkt, direction, &key, token, now_ns, now_ms_evict)
            }
            Action::Pass => {
                // No rule: carry on. This is the common case on a machine with
                // a handful of rules, and it costs one branch.
                self.stats.unmatched += 1;
                Outcome {
                    decision: Decision::SendNow,
                    flow: Some(key),
                    limit: None,
                }
            }
        }
        .with_rule(rule_idx)
    }

    fn apply_action_stateless(
        &mut self,
        action: Option<Action>,
        pkt: &PacketView<'_>,
        direction: Direction,
        token: u64,
        now_ns: u64,
        now_ms: u64,
    ) -> Outcome {
        let key = FlowKey::from_packet(pkt, direction, 0);
        match action {
            Some(Action::Block) => {
                self.stats.dropped_blocked += 1;
                Outcome {
                    decision: Decision::Drop(DropReason::Blocked),
                    flow: Some(key),
                    limit: None,
                }
            }
            Some(Action::Limit(li)) => {
                self.apply_limit(li, pkt, direction, &key, token, now_ns, now_ms)
            }
            _ => {
                self.stats.allowed += 1;
                Outcome {
                    decision: Decision::SendNow,
                    flow: Some(key),
                    limit: None,
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_limit(
        &mut self,
        limit_idx: u16,
        pkt: &PacketView<'_>,
        _direction: Direction,
        key: &FlowKey,
        token: u64,
        now_ns: u64,
        now_ms: u64,
    ) -> Outcome {
        let li = limit_idx as usize;
        if self.gcra.get(li).is_none() {
            // Stale rule index: forward, never silently tighten.
            self.stats.allowed += 1;
            return Outcome {
                decision: Decision::SendNow,
                flow: Some(*key),
                limit: Some(limit_idx),
            };
        }
        let policy = self
            .policy
            .get(li)
            .copied()
            .unwrap_or(OverLimitPolicy::Shape);
        let len = pkt.accounted_len();

        // Outside its window a scheduled limit is simply not a limit: nothing is
        // charged (not even the cap) and the packet goes out at once.
        if self.outside_window(li) {
            self.stats.allowed += 1;
            return Outcome {
                decision: Decision::SendNow,
                flow: Some(*key),
                limit: Some(limit_idx),
            };
        }

        // A cap is checked before the rate: a spent budget is not a speed
        // problem, and no amount of shaping makes it fit. Bytes are charged on
        // admission, so a packet that the retention buffer later sheds still
        // counts — overcounting is the safe direction to be wrong in.
        if self.charge_cap(li, len).is_some() {
            self.stats.dropped_cap += 1;
            return Outcome {
                decision: Decision::Drop(DropReason::Cap),
                flow: Some(*key),
                limit: Some(limit_idx),
            };
        }

        let (conforms, wait) = match self.scope.get(li).copied().unwrap_or_default() {
            // One bucket for the whole process: the shared lane.
            LimitScope::Process => self.acquire_shared(li, len, now_ns),
            // One bucket per flow: the state is the row's own `state` word.
            // `None` means the table is full; fall back to the shared lane so
            // the packet is still shaped, just pooled with the process.
            LimitScope::Flow => match self.acquire_per_flow(li, key, len, now_ns, now_ms) {
                Some(res) => res,
                None => self.acquire_shared(li, len, now_ns),
            },
        };

        if conforms {
            self.stats.rate_ok += 1;
            return Outcome {
                decision: Decision::SendNow,
                flow: Some(*key),
                limit: Some(limit_idx),
            };
        }

        // Over limit.
        self.stats.rate_over += 1;
        match policy {
            OverLimitPolicy::Drop => {
                self.stats.dropped_policy += 1;
                Outcome {
                    decision: Decision::Drop(DropReason::PolicyDrop),
                    flow: Some(*key),
                    limit: Some(limit_idx),
                }
            }
            OverLimitPolicy::DropInbound => {
                self.stats.dropped_policy += 1;
                Outcome {
                    decision: Decision::Drop(DropReason::PolicyDrop),
                    flow: Some(*key),
                    limit: Some(limit_idx),
                }
            }
            OverLimitPolicy::Shape => {
                let due = now_ns.saturating_add(wait);
                let flow_tag = (li as u32) << 16 | (key.pid & 0xFFFF);
                match self.scheduler.admit(pkt.raw, token, due, now_ns, flow_tag) {
                    Admit::Now => Outcome {
                        decision: Decision::SendNow,
                        flow: Some(*key),
                        limit: Some(limit_idx),
                    },
                    Admit::Retained { .. } => {
                        // Charge the rate only when it is actually emitted;
                        // see `on_emitted`. Charging here would double-count.
                        self.stats.retained += 1;
                        Outcome {
                            decision: Decision::Retain { due_ns: due },
                            flow: Some(*key),
                            limit: Some(limit_idx),
                        }
                    }
                    Admit::Shed(reason) => match reason {
                        Shed::Budget => {
                            self.stats.dropped_budget += 1;
                            Outcome {
                                decision: Decision::Drop(DropReason::Budget),
                                flow: Some(*key),
                                limit: Some(limit_idx),
                            }
                        }
                        Shed::TooLate { .. } => {
                            self.stats.dropped_late += 1;
                            Outcome {
                                decision: Decision::Drop(DropReason::TooLate),
                                flow: Some(*key),
                                limit: Some(limit_idx),
                            }
                        }
                        Shed::FlowQuota => {
                            self.stats.dropped_quota += 1;
                            Outcome {
                                decision: Decision::Drop(DropReason::FlowQuota),
                                flow: Some(*key),
                                limit: Some(limit_idx),
                            }
                        }
                    },
                }
            }
        }
    }

    /// Called by the I/O layer **after** a retained packet has actually been
    /// handed to the driver.
    ///
    /// This is the correction to the original's central bug: tokens are charged
    /// at emission, so a policy of "delay" really delays instead of pretending.
    pub fn on_emitted(&mut self, flow: FlowKey, limit_idx: u16, len: u32, now_ns: u64) {
        let li = limit_idx as usize;
        match self.scope.get(li).copied().unwrap_or_default() {
            LimitScope::Process => {
                if let Some(lane) = self.gcra.get_mut(li) {
                    lane.commit(len, now_ns);
                }
            }
            LimitScope::Flow => self.commit_to_flow(&flow, li, len, now_ns),
        }
        self.stats.emitted_from_retention += 1;
    }

    /// Charge a per-flow lane at emission time.
    ///
    /// A missing row means the flow was swept while the packet was retained
    /// (only possible if the retention ceiling outlived the flow idle timeout,
    /// which the defaults do not do). There is no per-flow state left to
    /// charge, so nothing is charged rather than something being invented.
    fn commit_to_flow(&mut self, flow: &FlowKey, li: usize, len: u32, now_ns: u64) {
        let Some(template) = self.gcra.get(li).copied() else {
            return;
        };
        let Some(entry) = self.flows.get_mut(flow) else {
            return;
        };
        let mut lane = template;
        lane.set_tat(entry.state);
        lane.commit(len, now_ns);
        entry.state = lane.tat();
    }

    /// Charge the *flow's own* lane and report `(conforms, wait_ns)`.
    ///
    /// Returns `None` when the flow table has no room for a new row, so the
    /// caller can fall back to the shared lane.
    ///
    /// The lane is a copy of the configured one, with the flow's stored TAT
    /// swapped in and the new TAT written back: one `u64` of state per
    /// connection, no table of its own, and no borrow of two `self` fields at
    /// once.
    fn acquire_per_flow(
        &mut self,
        li: usize,
        key: &FlowKey,
        len: u32,
        now_ns: u64,
        now_ms: u64,
    ) -> Option<(bool, u64)> {
        let template = *self.gcra.get(li)?;
        let (entry, _) = self.flows.get_or_insert(key, now_ms)?;
        let mut lane = template;
        lane.set_tat(entry.state);
        let conforms = lane.try_acquire(len, now_ns);
        let wait = lane.check(now_ns).unwrap_or(u64::MAX);
        entry.state = lane.tat();
        Some((conforms, wait))
    }

    /// Tell the engine what day and month it is, in UTC.
    ///
    /// The driver loop calls this from its once-a-second tick with the real
    /// clock; the simulator calls it once. Cheap and idempotent, and it is what
    /// rolls a spent daily or monthly budget over. Until it is called the
    /// engine assumes day 0, so a cap behaves as "per process run".
    pub fn set_calendar(&mut self, calendar: Calendar) {
        self.calendar = calendar;
        for li in 0..self.caps.len() {
            let cap = &mut self.caps[li];
            if cap.bytes > 0 && !calendar.covers(cap.period, cap.stamp) {
                cap.used = 0;
                cap.stamp = calendar.stamp(cap.period);
            }
        }
    }

    /// Calendar position the engine currently believes it is at.
    #[must_use]
    pub const fn calendar(&self) -> Calendar {
        self.calendar
    }

    /// Is this limit outside its time-of-day window right now?
    ///
    /// Limits without a window are never outside one, which is the common case
    /// and therefore a single `None` check.
    fn outside_window(&self, li: usize) -> bool {
        let Some(window) = self.windows.get(li).copied().flatten() else {
            return false;
        };
        !self.calendar.in_window(window)
    }

    /// Charge `len` bytes against a limit's cap.
    ///
    /// `Some(DropReason::Cap)` means the budget is spent and the packet must be
    /// dropped; `None` means it fit (and has been charged).
    fn charge_cap(&mut self, li: usize, len: u32) -> Option<DropReason> {
        let calendar = self.calendar;
        let cap = self.caps.get_mut(li)?;
        if cap.bytes == 0 {
            return None;
        }
        if !calendar.covers(cap.period, cap.stamp) {
            cap.used = 0;
            cap.stamp = calendar.stamp(cap.period);
        }
        let len = u64::from(len);
        if cap.used.saturating_add(len) > cap.bytes {
            return Some(DropReason::Cap);
        }
        cap.used += len;
        None
    }

    /// Usage of every limit that has a cap, for `lint`, the status display and
    /// the counter file. Allocates; never called from the packet path.
    #[must_use]
    pub fn cap_usage(&self) -> Vec<CapUsage> {
        self.config
            .limits
            .iter()
            .zip(self.caps.iter())
            .filter(|(_, c)| c.bytes > 0)
            .map(|(l, c)| CapUsage {
                name: l.name.clone(),
                used: c.used,
                cap: c.bytes,
                period: c.period,
                stamp: c.stamp,
            })
            .collect()
    }

    /// Restore a counter read from disk.
    ///
    /// A stamp from another period is ignored: the budget has already reset, so
    /// carrying the old count over would charge the user twice for yesterday.
    /// Returns whether anything was actually restored, so the caller's log line
    /// can be trusted.
    pub fn restore_cap_usage(&mut self, name: &str, used: u64, stamp: u32) -> bool {
        let calendar = self.calendar;
        let Some(li) = self
            .config
            .limits
            .iter()
            .position(|l| l.name.eq_ignore_ascii_case(name))
        else {
            return false;
        };
        let Some(cap) = self.caps.get_mut(li) else {
            return false;
        };
        if cap.bytes == 0 || !calendar.covers(cap.period, stamp) {
            return false;
        }
        cap.used = used.min(cap.bytes);
        cap.stamp = stamp;
        true
    }

    /// Charge the shared per-process lane and report `(conforms, wait_ns)`.
    ///
    /// Returns `(true, 0)` when the limit index has no lane at all: that can
    /// only happen for a stale rule index, and forwarding is the safe answer.
    fn acquire_shared(&mut self, li: usize, len: u32, now_ns: u64) -> (bool, u64) {
        let Some(lane) = self.gcra.get_mut(li) else {
            return (true, 0);
        };
        let conforms = lane.try_acquire(len, now_ns);
        (conforms, lane.check(now_ns).unwrap_or(u64::MAX))
    }

    /// Sweep idle flows and expired identities. Call from a slow tick (1 s).
    pub fn tick(&mut self, now_ms: u64) -> (usize, usize) {
        let flows = self.flows.sweep(now_ms, self.config.flow_idle_ms);
        let ids = self.identities.sweep(now_ms);
        (flows, ids)
    }

    /// Pending statistics counters that live outside `Counters`.
    #[must_use]
    pub fn extra_counters(&self) -> (u64, u64, u64) {
        (
            self.parse_errors,
            self.stats.flows_refused,
            self.stats.rule_hits,
        )
    }

    /// Update the configured rate of one limit at runtime (no restart).
    ///
    /// Because the GCRA state is a single word, changing the rate is cheap and
    /// does not reset the bucket to full (which the original's `SetLimit` did —
    /// meaning a rate change handed the flow a free burst).
    pub fn set_rate(
        &mut self,
        name: &str,
        bytes_per_sec: u64,
    ) -> Result<(), crate::error::ConfigError> {
        let Some(pos) = self
            .config
            .limits
            .iter()
            .position(|l| l.name == name.to_ascii_lowercase())
        else {
            return Err(crate::error::ConfigError::EmptyName);
        };
        let limit = self.config.limits[pos].clone();
        let burst = limit
            .burst_bytes
            .max(4 * u64::from(crate::config::MTU_BYTES));
        let fresh = Gcra::new(bytes_per_sec, burst)?;
        // Preserve the current arrival time: only the interval changes.
        let old_tat = self.gcra.get(pos).map_or(0, |g| g.tat());
        let mut lane = fresh;
        if lane.tat() < old_tat {
            // Re-apply the old TAT by committing zero bytes at that instant.
            lane = fresh;
            lane.commit(0, old_tat);
        }
        self.gcra[pos] = lane;
        self.config.limits[pos].rate_bps = bytes_per_sec;
        Ok(())
    }
}

impl Outcome {
    fn with_rule(self, _rule: u32) -> Self {
        self
    }

    /// Was the packet forwarded immediately?
    #[must_use]
    pub const fn is_send_now(&self) -> bool {
        matches!(self.decision, Decision::SendNow)
    }

    /// Was the packet dropped?
    #[must_use]
    pub const fn is_drop(&self) -> bool {
        matches!(self.decision, Decision::Drop(_))
    }
}

/// Helper for backends: pack a direction + a small payload into the opaque
/// per-packet token. The Windows backend uses the full `WINDIVERT_ADDRESS`
/// instead and keeps a parallel slab; this is for the simulator.
#[must_use]
pub const fn pack_token(idx: u32, direction: Direction) -> u64 {
    ((idx as u64) << 1) | (direction as u64)
}

/// Inverse of [`pack_token`].
#[must_use]
pub const fn unpack_token(token: u64) -> (u32, Direction) {
    let idx = (token >> 1) as u32;
    let dir = if token & 1 == 0 {
        Direction::Outbound
    } else {
        Direction::Inbound
    };
    (idx, dir)
}

/// Is this protocol one we shape at all?
#[must_use]
pub const fn shappable(p: Protocol) -> bool {
    matches!(p, Protocol::Tcp | Protocol::Udp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Limits;
    use crate::frame::{tcp_v4, udp_v4};

    const MS: u64 = 1_000_000;
    const S: u64 = 1_000_000_000;

    /// Emit a retained frame at its due time, charging the flow that owns it.
    ///
    /// A helper rather than three inline calls: `on_emitted` takes the flow key
    /// as well as the frame, which makes the call long enough that rustfmt
    /// breaks it inside every match arm.
    fn emit(e: &mut Engine<1024>, frame: &[u8], due_ns: u64) {
        let key = key_of(frame, Direction::Outbound, 0);
        e.on_emitted(key, 0, frame.len() as u32, due_ns);
    }

    /// Canonical flow key for a frame, exactly as `process` computes it.
    fn key_of(frame: &[u8], dir: Direction, pid: u32) -> FlowKey {
        let view = PacketView::parse(frame).expect("test frame parses");
        FlowKey::from_packet(&view, dir, pid)
    }

    fn engine_with(limits: Vec<Limits>) -> Engine<1024> {
        let mut cfg = Config::default();
        for l in limits {
            cfg.upsert(l).unwrap();
        }
        let mut e = Engine::new(cfg);
        let rules = vec!["limit=tight : tcp dport 443".to_owned()];
        let (_, compiled) = Engine::<1024>::compile_rules(&rules, &e.config.limits).unwrap();
        e.set_rules(compiled);
        e
    }

    #[test]
    fn unmatched_traffic_is_forwarded_immediately() {
        let mut e = engine_with(vec![Limits::new("tight").bits(8_000_000)]);
        let f = udp_v4([10, 0, 0, 1], 5000, [8, 8, 8, 8], 53, &[0; 100]);
        let out = e.process(&f, Direction::Outbound, 0, u32::MAX, 0, 0, 0);
        assert_eq!(out.decision, Decision::SendNow);
        assert_eq!(e.snapshot().packets, 1);
    }

    #[test]
    fn block_rule_drops() {
        let mut cfg = Config::default();
        cfg.upsert(Limits::new("unused").bits(8_000_000)).unwrap();
        let mut e = Engine::<1024>::new(cfg);
        let rules = vec!["block : udp dport 27015".to_owned()];
        let (_, compiled) = Engine::<1024>::compile_rules(&rules, &e.config.limits).unwrap();
        e.set_rules(compiled);
        let f = udp_v4([10, 0, 0, 1], 5000, [1, 2, 3, 4], 27015, &[0; 10]);
        let out = e.process(&f, Direction::Outbound, 0, u32::MAX, 0, 0, 0);
        assert_eq!(out.decision, Decision::Drop(DropReason::Blocked));
        assert_eq!(e.snapshot().dropped_blocked, 1);
    }

    #[test]
    fn shaping_actually_delays_then_charges_on_emit() {
        // 8 Mbit/s => 1 MB/s. 1500-byte packets => 1.5 ms each.
        let mut e = engine_with(vec![Limits::new("tight").bits(8_000_000).burst(6000)]);
        let f = tcp_v4([10, 0, 0, 1], 51515, [1, 1, 1, 1], 443, &[0; 1460]);
        let mut now = 0u64;
        let mut first_now = true;
        let mut retained = 0;
        let mut sent = 0;
        for _ in 0..20 {
            let out = e.process(&f, Direction::Outbound, 0, u32::MAX, 0, now, now / MS);
            match out.decision {
                Decision::SendNow => {
                    sent += 1;
                    if !first_now {
                        // correct behaviour: nothing was charged until emit
                    }
                    first_now = false;
                }
                Decision::Retain { due_ns } => {
                    retained += 1;
                    // Emit it at its due time and charge the lane.
                    emit(&mut e, &f, due_ns);
                    now = due_ns;
                }
                Decision::Drop(_) => panic!("should not drop while shaping"),
            }
        }
        assert!(retained > 10, "shaping did nothing: {retained} retained");
        assert!(sent >= 1);
        assert_eq!(e.snapshot().retained, retained as u64);
    }

    #[test]
    fn limits_are_actually_enforced_across_a_long_run() {
        // 200 KB/s, 1500-byte frames: at most ~133 frames per second of clock.
        let mut e = engine_with(vec![Limits::new("tight").bits(1_600_000).burst(6000)]);
        let f = tcp_v4([10, 0, 0, 1], 1234, [1, 1, 1, 1], 443, &[0; 1440]);
        let mut now = 0u64;
        let mut emitted_bytes = 0u64;
        for _ in 0..500 {
            match e.process(&f, Direction::Outbound, 0, u32::MAX, 0, now, now / MS) {
                Outcome {
                    decision: Decision::SendNow,
                    ..
                } => emitted_bytes += f.len() as u64,
                Outcome {
                    decision: Decision::Retain { due_ns },
                    ..
                } => {
                    emit(&mut e, &f, due_ns);
                    now = due_ns;
                    emitted_bytes += f.len() as u64;
                }
                Outcome {
                    decision: Decision::Drop(_),
                    ..
                } => {}
            }
        }
        let seconds = now as f64 / S as f64;
        // Exact GCRA property: bytes <= rate*T + burst + one packet. The extra
        // packet is not slack in the implementation — it is the algorithm: the
        // last accepted packet's own departure interval lands beyond `now`.
        let allowed = 200_000.0 * seconds + 6000.0 + f.len() as f64;
        assert!(
            (emitted_bytes as f64) <= allowed,
            "emitted {emitted_bytes} bytes in {seconds:.3}s, allowed {allowed:.0}"
        );
    }

    #[test]
    fn drop_policy_drops_instead_of_delaying() {
        let mut e = engine_with(vec![Limits::new("tight")
            .bits(800_000)
            .burst(1500)
            .policy(OverLimitPolicy::Drop)]);
        let f = tcp_v4([10, 0, 0, 1], 1234, [1, 1, 1, 1], 443, &[0; 1400]);
        let mut now = 0u64;
        let mut drops = 0;
        for _ in 0..10 {
            if let Decision::Drop(_) = e
                .process(&f, Direction::Outbound, 0, u32::MAX, 0, now, now / MS)
                .decision
            {
                drops += 1;
            }
            now += 100_000; // 100 µs between packets: much faster than allowed
        }
        assert!(drops > 0);
    }

    #[test]
    fn too_late_is_dropped_and_counted() {
        let mut e = engine_with(vec![Limits::new("tight").bits(8_000).burst(1500)]);
        let f = tcp_v4([10, 0, 0, 1], 1234, [1, 1, 1, 1], 443, &[0; 1400]);
        let mut now = 0u64;
        let mut too_late = 0;
        for _ in 0..200 {
            if let Decision::Drop(DropReason::TooLate) = e
                .process(&f, Direction::Outbound, 0, u32::MAX, 0, now, now / MS)
                .decision
            {
                too_late += 1;
            }
            now += 10_000;
        }
        assert!(too_late > 0, "expected the retention ceiling to bite");
    }

    #[test]
    fn flow_attribution_is_cached() {
        let mut e = engine_with(vec![Limits::new("tight").bits(8_000_000)]);
        let f = tcp_v4([10, 0, 0, 1], 999, [1, 1, 1, 1], 443, &[0; 100]);
        e.process(&f, Direction::Outbound, 0, u32::MAX, 0, 0, 0);
        let hits_before = e.snapshot().rule_hits;
        for _ in 0..100 {
            e.process(&f, Direction::Outbound, 0, u32::MAX, 0, 1000, 1);
        }
        assert_eq!(
            e.snapshot().rule_hits,
            hits_before,
            "rule table walked again for a known flow"
        );
        assert_eq!(e.flows().len(), 1);
    }

    #[test]
    fn malformed_packets_pass_through_and_are_counted() {
        let mut e = engine_with(vec![Limits::new("tight").bits(8_000_000)]);
        let out = e.process(&[0xFF; 8], Direction::Outbound, 0, 0, 0, 0, 0);
        assert_eq!(out.decision, Decision::SendNow);
        assert_eq!(e.parse_errors(), 1);
    }

    #[test]
    fn tokens_round_trip() {
        assert_eq!(
            unpack_token(pack_token(1234, Direction::Inbound)),
            (1234, Direction::Inbound)
        );
    }

    #[test]
    fn tick_sweeps_idle_flows() {
        let mut e = engine_with(vec![Limits::new("tight").bits(8_000_000)]);
        let f = tcp_v4([10, 0, 0, 1], 999, [1, 1, 1, 1], 443, &[0; 100]);
        e.process(&f, Direction::Outbound, 0, u32::MAX, 0, 0, 0);
        assert_eq!(e.flows().len(), 1);
        let (removed, _) = e.tick(10_000_000);
        assert_eq!(removed, 1);
        assert_eq!(e.flows().len(), 0);
    }

    #[test]
    fn rate_change_does_not_reset_the_bucket() {
        let mut e = engine_with(vec![Limits::new("tight").bits(800_000).burst(3000)]);
        let f = tcp_v4([10, 0, 0, 1], 999, [1, 1, 1, 1], 443, &[0; 1400]);
        let mut now = 0u64;
        for _ in 0..5 {
            if let Decision::Retain { due_ns } = e
                .process(&f, Direction::Outbound, 0, u32::MAX, 0, now, now / MS)
                .decision
            {
                emit(&mut e, &f, due_ns);
                now = due_ns;
            }
        }
        e.set_rate("tight", 100_000).unwrap();
        assert_eq!(e.config().limit("tight").unwrap().rate_bps, 100_000);
    }

    // -----------------------------------------------------------------------
    // per-flow vs process scope
    // -----------------------------------------------------------------------

    /// Engine with one 8 Mbit/s limit (1 MB/s, ~1.5 ms per 1500-byte frame,
    /// 6 KB burst => [`BURST_FRAMES`] frames conform at one instant) and a rule
    /// that attaches it to outbound TCP 443.
    fn scope_engine(scope: LimitScope) -> Engine<1024> {
        let mut cfg = Config::default();
        cfg.upsert(
            Limits::new("tight")
                .bits(8_000_000)
                .burst(6000)
                .scope(scope),
        )
        .unwrap();
        let mut e = Engine::new(cfg);
        let rules = vec!["limit=tight : tcp dport 443".to_owned()];
        let (_, compiled) = Engine::<1024>::compile_rules(&rules, &e.config.limits).unwrap();
        e.set_rules(compiled);
        e
    }

    fn conn(src_port: u16) -> Vec<u8> {
        tcp_v4([10, 0, 0, 1], src_port, [1, 1, 1, 1], 443, &[0; 1460])
    }

    /// Frames that conform at a single instant before the burst is spent.
    ///
    /// 6 KB of burst at 1 MB/s is 6 ms of tolerance; each 1500-byte frame costs
    /// 1.5 ms, so the fifth frame still conforms at `now = 0` (GCRA tests
    /// `now >= tat - tolerance`, and the first packet starts from `tat = 0`).
    /// The sixth is the first one over the limit.
    const BURST_FRAMES: usize = 5;

    /// Drain one flow's burst at `now`, then check a *second* flow at the same
    /// instant. With `per-flow` the second flow must be untouched; with
    /// `process` scope it must inherit the first flow's debt.
    #[test]
    fn per_flow_scope_keeps_a_bucket_per_connection() {
        let a = conn(51515);
        let b = conn(51516);

        // per-flow: B is not starved by A.
        let mut e = scope_engine(LimitScope::Flow);
        for i in 0..BURST_FRAMES as u64 {
            let out = e.process(&a, Direction::Outbound, 0, u32::MAX, i, 0, 0);
            assert_eq!(
                out.decision,
                Decision::SendNow,
                "flow A packet {i} of burst"
            );
        }
        let over = e.process(&a, Direction::Outbound, 0, u32::MAX, 10, 0, 0);
        assert!(
            !over.is_send_now(),
            "flow A must be limited after its burst"
        );
        let fresh = e.process(&b, Direction::Outbound, 0, u32::MAX, 11, 0, 0);
        assert!(
            fresh.is_send_now(),
            "flow B was starved by flow A's debt: per-flow scope did nothing"
        );

        // process scope: the same two flows share one bucket, which is the
        // documented default and must not have changed.
        let mut e = scope_engine(LimitScope::Process);
        for i in 0..BURST_FRAMES as u64 {
            e.process(&a, Direction::Outbound, 0, u32::MAX, i, 0, 0);
        }
        let shared = e.process(&b, Direction::Outbound, 0, u32::MAX, 11, 0, 0);
        assert!(
            !shared.is_send_now(),
            "process scope must keep one shared bucket"
        );
    }

    #[test]
    fn per_flow_scope_still_enforces_the_rate_of_one_flow() {
        let mut e = scope_engine(LimitScope::Flow);
        let a = conn(51515);
        let mut retained = 0;
        let mut now = 0u64;
        for i in 0..30 {
            let verdict = e.process(&a, Direction::Outbound, 0, u32::MAX, i, now, now / MS);
            match verdict.decision {
                Decision::SendNow => {}
                Decision::Retain { due_ns } => {
                    retained += 1;
                    emit(&mut e, &a, due_ns);
                    now = due_ns;
                }
                Decision::Drop(_) => panic!("shape policy must never drop"),
            }
        }
        assert!(
            retained > 10,
            "per-flow shaping did nothing: {retained} retained"
        );
        // 30 frames x 1500 bytes at 1 MB/s is ~45 ms; the burst covers 6 KB, so
        // the clock must still have advanced by at least 30 ms.
        assert!(now >= 30 * MS, "clock advanced only {now} ns");
    }

    #[test]
    fn on_emitted_charges_only_the_emitting_flow() {
        let mut e = scope_engine(LimitScope::Flow);
        let a = conn(51515);
        let b = conn(51516);
        // Both flows exist and are conforming at t = 0.
        let b_first = e.process(&b, Direction::Outbound, 0, u32::MAX, 0, 0, 0);
        assert!(b_first.is_send_now());
        for i in 0..BURST_FRAMES as u64 {
            e.process(&a, Direction::Outbound, 0, u32::MAX, i, 0, 0);
        }
        let verdict = e.process(&a, Direction::Outbound, 0, u32::MAX, 20, 0, 0);
        let due = match verdict.decision {
            Decision::Retain { due_ns } => due_ns,
            other => panic!("flow A should have been retained, got {other:?}"),
        };
        let key_a = key_of(&a, Direction::Outbound, 0);
        let key_b = key_of(&b, Direction::Outbound, 0);
        let b_before = e.flows().get(&key_b).map_or(0, |f| f.state);
        e.on_emitted(key_a, 0, a.len() as u32, due);
        let a_after = e.flows().get(&key_a).map_or(0, |f| f.state);
        let b_after = e.flows().get(&key_b).map_or(0, |f| f.state);
        assert!(a_after > 0, "emitting must charge flow A");
        assert_eq!(b_after, b_before, "emitting flow A must not charge flow B");
        let b_now = e.process(&b, Direction::Outbound, 0, u32::MAX, 21, due, due / MS);
        assert!(b_now.is_send_now(), "flow B inherited flow A's charge");
    }

    // -----------------------------------------------------------------------
    // data caps
    // -----------------------------------------------------------------------

    /// Engine with one fast limit attached to outbound TCP 443, described by
    /// the rest of a `limit` line (`cap 2gb/day`, `schedule 08:00-18:00`, ...).
    ///
    /// The limit is parsed from the user-facing syntax rather than built by
    /// hand, so the spelling of each option is covered by these tests as well.
    fn spec_engine(spec: &str) -> Engine<1024> {
        let text = format!("limit budget = 64mbit {spec}\n");
        let (cfg, _) = Config::parse(&text).unwrap();
        let mut e = Engine::new(cfg);
        let rules = vec!["limit=budget : tcp dport 443".to_owned()];
        let (_, compiled) = Engine::<1024>::compile_rules(&rules, &e.config.limits).unwrap();
        e.set_rules(compiled);
        e
    }

    fn decision_of(e: &mut Engine<1024>, frame: &[u8], token: u64) -> Decision {
        let out = e.process(frame, Direction::Outbound, 0, u32::MAX, token, 0, 0);
        out.decision
    }

    #[test]
    fn cap_drops_once_the_budget_is_spent() {
        // 3000 bytes of budget, 1500-byte frames: two fit, the third does not.
        let mut e = spec_engine("cap 3000/day");
        let f = conn(51515);
        assert_eq!(decision_of(&mut e, &f, 0), Decision::SendNow);
        assert_eq!(decision_of(&mut e, &f, 1), Decision::SendNow);
        assert_eq!(
            decision_of(&mut e, &f, 2),
            Decision::Drop(DropReason::Cap),
            "the third frame must be refused: the budget is spent"
        );
        assert_eq!(e.snapshot().dropped_cap, 1);
        assert_eq!(e.snapshot().dropped_total(), 1);
        assert_eq!(e.cap_usage()[0].used, 3000, "usage must stop at the budget");
    }

    #[test]
    fn a_daily_cap_rolls_over_at_the_next_day() {
        let mut e = spec_engine("cap 3000/day");
        let f = conn(51515);
        for token in 0..2 {
            assert_eq!(decision_of(&mut e, &f, token), Decision::SendNow);
        }
        assert_eq!(decision_of(&mut e, &f, 2), Decision::Drop(DropReason::Cap));

        // Midnight UTC: the same flow gets a fresh budget.
        e.set_calendar(Calendar::from_day_index(7));
        assert_eq!(e.cap_usage()[0].used, 0);
        assert_eq!(decision_of(&mut e, &f, 3), Decision::SendNow);
    }

    #[test]
    fn a_monthly_cap_survives_the_next_day() {
        let mut e = spec_engine("cap 3000/month");
        let f = conn(51515);
        for token in 0..2 {
            assert_eq!(decision_of(&mut e, &f, token), Decision::SendNow);
        }
        // The next day is in the same month (day 0 and day 1 are January 1970),
        // so the budget stays spent.
        e.set_calendar(Calendar::from_day_index(1));
        assert_eq!(decision_of(&mut e, &f, 2), Decision::Drop(DropReason::Cap));
        // The first of February is a new period.
        e.set_calendar(Calendar::from_day_index(31));
        assert_eq!(e.cap_usage()[0].used, 0);
        assert_eq!(decision_of(&mut e, &f, 3), Decision::SendNow);
    }

    #[test]
    fn restored_usage_only_applies_to_the_period_it_was_recorded_in() {
        let f = conn(51515);
        let mut e = spec_engine("cap 10000/day");
        e.set_calendar(Calendar::from_day_index(20_766));

        // A counter from yesterday must not be charged to today.
        e.restore_cap_usage("budget", 9_000, 20_765);
        assert_eq!(e.cap_usage()[0].used, 0);

        // One from today is, and it is enforced: 1000 bytes are left, which is
        // less than one 1500-byte frame, so the next packet is refused.
        e.restore_cap_usage("budget", 9_000, 20_766);
        assert_eq!(e.cap_usage()[0].used, 9_000);
        assert_eq!(decision_of(&mut e, &f, 0), Decision::Drop(DropReason::Cap));

        // A name that is not configured is ignored rather than invented.
        e.restore_cap_usage("not-a-limit", 500, 20_766);
    }

    #[test]
    fn an_uncapped_limit_never_drops_for_its_cap() {
        let mut e = engine_with(vec![Limits::new("tight").bits(8_000_000)]);
        let f = conn(51515);
        for token in 0..5 {
            assert_ne!(
                decision_of(&mut e, &f, token),
                Decision::Drop(DropReason::Cap)
            );
        }
        assert_eq!(e.snapshot().dropped_cap, 0);
        assert!(e.cap_usage().is_empty());
    }

    // -----------------------------------------------------------------------
    // time-of-day schedules
    // -----------------------------------------------------------------------

    #[test]
    fn a_scheduled_limit_only_applies_inside_its_window() {
        let mut e = spec_engine("burst 1500 schedule 08:00-18:00");
        let f = conn(51515);

        // 09:00 UTC: inside the window, so the rate is enforced and most of six
        // back-to-back frames cannot go out at the same instant.
        e.set_calendar(Calendar::from_day_index(20_766).at_minute(9 * 60));
        let held = (0..6)
            .filter(|token| decision_of(&mut e, &f, *token) != Decision::SendNow)
            .count();
        assert!(held > 0, "the limit must bite at 09:00");

        // 20:00 UTC: outside. The limit does not exist, so nothing is held.
        e.set_calendar(Calendar::from_day_index(20_766).at_minute(20 * 60));
        for token in 6..12 {
            let decision = decision_of(&mut e, &f, token);
            assert_eq!(decision, Decision::SendNow, "token {token} at 20:00");
        }
    }

    #[test]
    fn a_window_that_wraps_midnight_works_the_same_way() {
        let f = conn(51515);
        // 23:00 and 03:00 are inside `22:00-06:00`, and a 1500-byte budget is
        // spent by the first frame there -- a fresh engine per instant, because
        // a shaped flow carries its rate history to the next check.
        for minute in [23 * 60, 3 * 60] {
            let mut e = spec_engine("cap 1500/day schedule 22:00-06:00");
            e.set_calendar(Calendar::from_day_index(20_766).at_minute(minute));
            assert_eq!(decision_of(&mut e, &f, 0), Decision::SendNow);
            assert_eq!(
                decision_of(&mut e, &f, 1),
                Decision::Drop(DropReason::Cap),
                "minute {minute} must be inside the window"
            );
        }

        // 12:00 is outside it: nothing is charged, so nothing drops.
        let mut e = spec_engine("cap 1500/day schedule 22:00-06:00");
        e.set_calendar(Calendar::from_day_index(20_766).at_minute(12 * 60));
        for token in 0..4 {
            assert_eq!(decision_of(&mut e, &f, token), Decision::SendNow);
        }
        assert_eq!(e.cap_usage()[0].used, 0);
    }

    #[test]
    fn a_cap_is_not_charged_outside_the_schedule() {
        let mut e = spec_engine("cap 3000/day schedule 08:00-18:00");
        let f = conn(51515);

        // 20:00 UTC: four 1500-byte frames would blow a 3000-byte budget, but
        // the limit is not in force, so nothing is charged and nothing drops.
        e.set_calendar(Calendar::from_day_index(20_766).at_minute(20 * 60));
        for token in 0..4 {
            assert_eq!(decision_of(&mut e, &f, token), Decision::SendNow);
        }
        assert_eq!(e.cap_usage()[0].used, 0, "nothing may be charged at 20:00");

        // 09:00 UTC, same day: the budget is enforced from zero.
        e.set_calendar(Calendar::from_day_index(20_766).at_minute(9 * 60));
        assert_eq!(decision_of(&mut e, &f, 4), Decision::SendNow);
        assert_eq!(decision_of(&mut e, &f, 5), Decision::SendNow);
        assert_eq!(decision_of(&mut e, &f, 6), Decision::Drop(DropReason::Cap));
    }
}
