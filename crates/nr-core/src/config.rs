//! Configuration: typed, validated, and parsed without a dependency tree.
//!
//! The whole configuration is a plain text file (see `docs/CONFIG.md`). We do
//! not pull `serde`/`toml` into the core: every dependency is startup time,
//! binary size and a supply-chain surface, and a daemon that has to feel like a
//! rocket should not spend 40 ms parsing a 20-line file.
//!
//! Format:
//!
//! ```text
//! # comments start with '#'
//! param queue-length = 1024
//! param queue-time   = 500ms
//! limit chrome.exe  = 8mbit   burst 64kb  policy shape
//! limit steam.exe   = 20mbit
//! limit browser.exe = 8mbit   per-flow
//! rule  limit=chrome.exe : tcp
//! rule  block : udp dport 27015
//! ```

use crate::error::ConfigError;
use crate::gcra::MIN_BURST;

/// Largest frame we plan for: Ethernet MTU payload. Used to keep bursts and
/// budgets from being configured smaller than one packet.
pub const MTU_BYTES: u32 = 1500;

/// What to do when a flow would exceed its limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum OverLimitPolicy {
    /// Delay the packet until it conforms. Preserves throughput and keeps the
    /// congestion window intact. This is the default because it does not waste
    /// bandwidth: nothing is retransmitted.
    #[default]
    Shape = 0,
    /// Drop outbound packets that do not conform. Cheapest, but TCP retransmits
    /// them, which is the *bandwidth-wasting* option.
    Drop = 1,
    /// Drop inbound packets that do not conform (yields a zero window, so the
    /// peer slows down instead of retransmitting into a wall).
    DropInbound = 2,
}

impl OverLimitPolicy {
    /// Parse from the config file spelling.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "shape" | "delay" => Some(Self::Shape),
            "drop" | "clip" => Some(Self::Drop),
            "drop-inbound" | "dropin" => Some(Self::DropInbound),
            _ => None,
        }
    }

    /// Stable spelling for logs/diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Shape => "shape",
            Self::Drop => "drop",
            Self::DropInbound => "drop-inbound",
        }
    }
}

/// What a limit's bucket is shared between.
///
/// The original implementation had exactly one bucket per rule, so one
/// aggressive transfer starved every other connection the same process owned
/// (a browser streaming 4K starves its own DNS lookups). [`LimitScope::Flow`]
/// gives each connection its own bucket instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum LimitScope {
    /// One bucket per process: every flow the process opens shares the rate.
    /// This is the historical behaviour and the default.
    #[default]
    Process = 0,
    /// One bucket per flow: each connection gets the full configured rate.
    Flow = 1,
}

impl LimitScope {
    /// Parse from the config file spelling.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "process" | "proc" | "shared" => Some(Self::Process),
            "per-flow" | "perflow" | "flow" | "connection" => Some(Self::Flow),
            _ => None,
        }
    }

    /// Stable spelling for the config file, logs and diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Process => "process",
            Self::Flow => "per-flow",
        }
    }

    /// Spelling used in a `limit` line (`per-flow` is a bare token there).
    #[must_use]
    pub const fn as_token(self) -> &'static str {
        match self {
            Self::Process => "process",
            Self::Flow => "per-flow",
        }
    }
}

/// How often a data cap resets.
///
/// Both periods are **UTC** boundaries: midnight UTC for [`CapPeriod::Day`] and
/// the first of the month for [`CapPeriod::Month`]. A local-time reset would
/// need a timezone database or an OS call, and "it resets at midnight UTC" is a
/// smaller surprise than an hour nobody can predict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum CapPeriod {
    /// Resets at 00:00 UTC.
    #[default]
    Day = 0,
    /// Resets on the first of the month, 00:00 UTC.
    Month = 1,
}

impl CapPeriod {
    /// Parse from the config file spelling.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "day" | "daily" | "d" => Some(Self::Day),
            "month" | "monthly" | "m" => Some(Self::Month),
            _ => None,
        }
    }

    /// Stable spelling for config files, logs and diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Day => "day",
            Self::Month => "month",
        }
    }
}

/// A byte budget for one limit, reset every [`CapPeriod`].
///
/// This is the feature a metered connection actually needs: a rate limit says
/// how fast, a cap says how much. Bytes are counted in **both** directions and
/// charged when a packet is admitted, not when it is emitted — overcounting a
/// packet the retention buffer later sheds is the safe direction to be wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cap {
    /// Budget in bytes.
    pub bytes: u64,
    /// Reset period.
    pub period: CapPeriod,
}

impl Cap {
    /// Build a cap.
    #[must_use]
    pub const fn new(bytes: u64, period: CapPeriod) -> Self {
        Self { bytes, period }
    }
}

/// A time-of-day window, in minutes since 00:00 UTC.
///
/// `start < end` is a window inside one day (`08:00-18:00`); `start > end`
/// wraps midnight (`22:00-06:00`), which is what "backups overnight" looks
/// like. The endpoints are **UTC** for the same reason caps are: local time
/// needs a timezone database or an OS call on the hot path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    /// First minute the window is active, inclusive.
    pub start_min: u16,
    /// Minute it stops being active, exclusive.
    pub end_min: u16,
}

impl Window {
    /// Build a window, if the endpoints describe a non-empty one.
    ///
    /// `start == end` is rejected: it is a zero-length window, which is either a
    /// typo or a request to disable the limit, and a config file should say
    /// which. Use two windows or remove the limit.
    #[must_use]
    pub const fn new(start_min: u16, end_min: u16) -> Option<Self> {
        if start_min == end_min || start_min >= MINUTES_PER_DAY || end_min >= MINUTES_PER_DAY {
            return None;
        }
        Some(Self {
            start_min,
            end_min,
        })
    }

    /// Parse `08:00-18:00`, `8-18`, or `22:30-06:15`.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let (a, b) = s.split_once('-')?;
        Self::new(parse_minute_of_day(a)?, parse_minute_of_day(b)?)
    }

    /// Does `minute` (0..1440) fall inside the window?
    #[must_use]
    pub const fn contains(self, minute: u16) -> bool {
        if self.start_min < self.end_min {
            minute >= self.start_min && minute < self.end_min
        } else {
            minute >= self.start_min || minute < self.end_min
        }
    }

    /// Does the window wrap midnight?
    #[must_use]
    pub const fn wraps(self) -> bool {
        self.start_min > self.end_min
    }
}

impl std::fmt::Display for Window {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:02}:{:02}-{:02}:{:02}",
            self.start_min / 60,
            self.start_min % 60,
            self.end_min / 60,
            self.end_min % 60
        )
    }
}

/// Minutes in a day.
pub const MINUTES_PER_DAY: u16 = 24 * 60;

/// `08`, `8`, `08:30` -> minutes since midnight (UTC).
///
/// Public because `simulate --at` needs the same spelling as a schedule, and
/// two parsers for one time of day is how they drift apart.
#[must_use]
pub fn parse_minute_of_day(s: &str) -> Option<u16> {
    let s = s.trim();
    let (h, m) = match s.split_once(':') {
        Some((h, m)) => (h, m),
        None => (s, "0"),
    };
    let h: u16 = h.parse().ok()?;
    let m: u16 = m.parse().ok()?;
    if h >= 24 || m >= 60 {
        return None;
    }
    Some(h * 60 + m)
}

/// One named bandwidth limit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// Stable name used by rules (`limit=chrome.exe`).
    pub name: String,
    /// Rate in bytes per second.
    pub rate_bps: u64,
    /// Burst in bytes.
    pub burst_bytes: u64,
    /// Over-limit policy.
    pub policy: OverLimitPolicy,
    /// Whether the bucket is shared by the process or kept per flow.
    pub scope: LimitScope,
    /// Optional byte budget that resets every day or month.
    pub cap: Option<Cap>,
    /// Optional time-of-day window in which this limit is enforced at all.
    pub window: Option<Window>,
}

impl Limits {
    /// Start a builder: `Limits::new("chrome.exe").bits(8_000_000)`.
    #[must_use]
    pub fn new(name: &str) -> Self {
        Self {
            name: name.trim().to_ascii_lowercase(),
            rate_bps: 0,
            burst_bytes: 64 * 1024,
            policy: OverLimitPolicy::Shape,
            scope: LimitScope::Process,
            cap: None,
            window: None,
        }
    }

    /// Enforce this limit only inside `window` (UTC minutes).
    #[must_use]
    pub fn window(mut self, window: Window) -> Self {
        self.window = Some(window);
        self
    }

    /// Give this limit a byte budget that resets every `period`.
    #[must_use]
    pub fn cap(mut self, bytes: u64, period: CapPeriod) -> Self {
        self.cap = Some(Cap::new(bytes, period));
        self
    }

    /// Give every flow its own bucket (see [`LimitScope`]).
    #[must_use]
    pub fn per_flow(mut self) -> Self {
        self.scope = LimitScope::Flow;
        self
    }

    /// Set the scope explicitly.
    #[must_use]
    pub fn scope(mut self, scope: LimitScope) -> Self {
        self.scope = scope;
        self
    }

    /// Set rate in bytes per second.
    #[must_use]
    pub fn rate(mut self, bytes_per_sec: u64) -> Self {
        self.rate_bps = bytes_per_sec;
        self
    }

    /// Set rate in bits per second (what humans type).
    #[must_use]
    pub fn bits(mut self, bits_per_sec: u64) -> Self {
        self.rate_bps = bits_per_sec / 8;
        self
    }

    /// Set burst in bytes.
    #[must_use]
    pub fn burst(mut self, bytes: u64) -> Self {
        self.burst_bytes = bytes;
        self
    }

    /// Set policy.
    #[must_use]
    pub fn policy(mut self, policy: OverLimitPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.name.is_empty() {
            return Err(ConfigError::EmptyName);
        }
        if self.rate_bps == 0 {
            return Err(ConfigError::ZeroRate);
        }
        if self.burst_bytes < MIN_BURST {
            return Err(ConfigError::BurstTooSmall {
                burst: self.burst_bytes,
            });
        }
        if self.cap.is_some_and(|c| c.bytes == 0) {
            return Err(ConfigError::ZeroCap);
        }
        Ok(())
    }

    /// Rate expressed in bits/s (for display).
    #[must_use]
    pub const fn rate_bps_to_bits(&self) -> u64 {
        self.rate_bps.saturating_mul(8)
    }
}

/// Tuning parameters exposed by WinDivert plus our own knobs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// `WinDivertSetParam(QUEUE_LENGTH)`; default 1024 (driver default is 4096,
    /// but our reader drains every 125 µs, so a shorter queue means *less*
    /// standing delay and no difference in loss).
    pub queue_length: u64,
    /// `QUEUE_TIME` in ms; default 400 (driver default 2000 ms is a bufferbloat
    /// factory for a shaper: a queued packet that waits is a packet the peer has
    /// already retransmitted).
    pub queue_time_ms: u64,
    /// `QUEUE_SIZE` in bytes; default 1 MiB (driver default 4 MiB).
    pub queue_size: u64,
    /// Maximum bytes we retain across batches. Bounded on purpose: over budget
    /// we shed instead of growing, so memory use is flat and provable.
    pub retain_budget_bytes: u64,
    /// Maximum time a packet may be retained before we give up on it. Beyond
    /// this, delivery is worse than loss (TCP already retransmitted).
    pub max_retain_ms: u64,
    /// Flow idle timeout before the row is swept.
    pub flow_idle_ms: u64,
    /// Packet batch size requested from `RecvEx` (1..=255).
    pub batch_max: u32,
    /// Reader wait timeout in ms; the loop blocks on the driver, not on a timer.
    pub recv_timeout_ms: u64,
    /// Identity cache TTL.
    pub identity_ttl_ms: u64,
    /// Named limits.
    pub limits: Vec<Limits>,
    /// Default over-limit policy for limits that do not override it.
    pub default_policy: OverLimitPolicy,
    /// Run without touching the network stack at all (simulator only).
    pub dry_run: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            queue_length: 1024,
            queue_time_ms: 400,
            queue_size: 1 << 20,
            retain_budget_bytes: 2 << 20,
            max_retain_ms: 250,
            flow_idle_ms: 120_000,
            batch_max: 64,
            recv_timeout_ms: 100,
            identity_ttl_ms: 30_000,
            limits: Vec::new(),
            default_policy: OverLimitPolicy::Shape,
            dry_run: false,
        }
    }
}

impl Config {
    /// Look up a limit by name (case-insensitive, matches already lowercased).
    #[must_use]
    pub fn limit(&self, name: &str) -> Option<&Limits> {
        let lname = name.trim().to_ascii_lowercase();
        self.limits.iter().find(|l| l.name == lname)
    }

    /// Add or replace a limit.
    pub fn upsert(&mut self, limit: Limits) -> Result<(), ConfigError> {
        limit.validate()?;
        match self.limits.iter_mut().find(|l| l.name == limit.name) {
            Some(slot) => *slot = limit,
            None => self.limits.push(limit),
        }
        Ok(())
    }

    /// Remove a limit by name.
    pub fn remove(&mut self, name: &str) -> bool {
        let lname = name.trim().to_ascii_lowercase();
        let before = self.limits.len();
        self.limits.retain(|l| l.name != lname);
        before != self.limits.len()
    }

    /// Validate every rule that had to be deferred (`limit=` names may be
    /// defined *after* the rule that references them).
    pub fn validate(&self) -> Result<(), ConfigError> {
        for l in &self.limits {
            l.validate()?;
        }
        Ok(())
    }

    /// Apply one `param key = value` line.
    pub fn set_param(&mut self, key: &str, value: &str) -> Result<(), ConfigError> {
        let k = key.trim().to_ascii_lowercase().replace('_', "-");
        let v = value.trim();
        let bad = || ConfigError::BadValue {
            key: k.clone(),
            value: v.to_owned(),
        };
        match k.as_str() {
            "queue-length" => self.queue_length = parse_u64(v).ok_or_else(bad)?,
            "queue-time" | "queue-time-ms" => {
                self.queue_time_ms = parse_duration_ms(v).ok_or_else(bad)?
            }
            "queue-size" | "queue-size-bytes" => self.queue_size = parse_size(v).ok_or_else(bad)?,
            "retain-budget" | "retain-budget-bytes" => {
                self.retain_budget_bytes = parse_size(v).ok_or_else(bad)?
            }
            "max-retain" | "max-retain-ms" => {
                self.max_retain_ms = parse_duration_ms(v).ok_or_else(bad)?
            }
            "flow-idle" | "flow-idle-ms" => {
                self.flow_idle_ms = parse_duration_ms(v).ok_or_else(bad)?
            }
            "batch-max" => self.batch_max = parse_u64(v).ok_or_else(bad)?.min(255) as u32,
            "recv-timeout" | "recv-timeout-ms" => {
                self.recv_timeout_ms = parse_duration_ms(v).ok_or_else(bad)?
            }
            "identity-ttl" | "identity-ttl-ms" => {
                self.identity_ttl_ms = parse_duration_ms(v).ok_or_else(bad)?
            }
            "default-policy" => {
                self.default_policy = OverLimitPolicy::parse(v).ok_or_else(bad)?;
            }
            "dry-run" => self.dry_run = matches!(v, "1" | "true" | "yes" | "on"),
            _ => return Err(ConfigError::UnknownParam(k)),
        }
        Ok(())
    }

    /// Read a whole configuration file.
    ///
    /// Rules are returned as raw strings because the rule compiler lives in
    /// [`crate::rules`] and needs the finished limit table to resolve names.
    pub fn parse(text: &str) -> Result<(Self, Vec<String>), ConfigError> {
        let mut cfg = Self::default();
        let mut rules = Vec::new();
        for (n, raw) in text.lines().enumerate() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let (head, rest) = split_keyword(line);
            match head {
                "param" => {
                    let (k, v) = rest.split_once('=').ok_or_else(|| ConfigError::BadValue {
                        key: format!("line {}", n + 1),
                        value: line.to_owned(),
                    })?;
                    cfg.set_param(k, v)?;
                }
                "limit" => cfg.upsert(parse_limit(rest)?)?,
                "rule" => rules.push(rest.to_owned()),
                other => return Err(ConfigError::UnknownParam(other.to_owned())),
            }
        }
        Ok((cfg, rules))
    }

    /// Serialise the parameters only (limits/rules are written by the caller so
    /// ordering inside the file stays stable).
    #[must_use]
    pub fn to_params_text(&self) -> String {
        let mut s = String::new();
        s.push_str("# netrocket configuration\n");
        s.push_str(&format!("param queue-length = {}\n", self.queue_length));
        s.push_str(&format!("param queue-time = {}ms\n", self.queue_time_ms));
        s.push_str(&format!("param queue-size = {}\n", self.queue_size));
        s.push_str(&format!(
            "param retain-budget = {}\n",
            self.retain_budget_bytes
        ));
        s.push_str(&format!("param max-retain = {}ms\n", self.max_retain_ms));
        s.push_str(&format!("param flow-idle = {}ms\n", self.flow_idle_ms));
        s.push_str(&format!("param batch-max = {}\n", self.batch_max));
        s.push_str(&format!(
            "param recv-timeout = {}ms\n",
            self.recv_timeout_ms
        ));
        s.push_str(&format!(
            "param identity-ttl = {}ms\n",
            self.identity_ttl_ms
        ));
        s.push_str(&format!(
            "param default-policy = {}\n",
            self.default_policy.as_str()
        ));
        s
    }
}

fn split_keyword(line: &str) -> (&str, &str) {
    match line.find(char::is_whitespace) {
        Some(i) => (&line[..i], line[i..].trim()),
        None => (line, ""),
    }
}

/// `chrome.exe = 8mbit burst 64kb policy shape`
fn parse_limit(rest: &str) -> Result<Limits, ConfigError> {
    let (name, tail) = rest.split_once('=').ok_or_else(|| ConfigError::BadValue {
        key: "limit".to_owned(),
        value: rest.to_owned(),
    })?;
    let mut tokens = tail.split_whitespace().peekable();
    let rate_tok = tokens.next().ok_or_else(|| ConfigError::BadValue {
        key: "limit.rate".to_owned(),
        value: rest.to_owned(),
    })?;
    let mut limit = Limits::new(name);
    limit.rate_bps = parse_rate(rate_tok).ok_or_else(|| ConfigError::BadValue {
        key: "limit.rate".to_owned(),
        value: rate_tok.to_owned(),
    })?;
    while let Some(tok) = tokens.next() {
        match tok.to_ascii_lowercase().as_str() {
            "burst" => {
                let v = tokens.next().ok_or_else(|| ConfigError::BadValue {
                    key: "limit.burst".to_owned(),
                    value: String::new(),
                })?;
                limit.burst_bytes = parse_size(v).ok_or_else(|| ConfigError::BadValue {
                    key: "limit.burst".to_owned(),
                    value: v.to_owned(),
                })?;
            }
            "policy" => {
                let v = tokens.next().ok_or_else(|| ConfigError::BadValue {
                    key: "limit.policy".to_owned(),
                    value: String::new(),
                })?;
                limit.policy = OverLimitPolicy::parse(v).ok_or_else(|| ConfigError::BadValue {
                    key: "limit.policy".to_owned(),
                    value: v.to_owned(),
                })?;
            }
            // `cap 50gb/day`, `cap 50gb per day`, `cap 50gb day` — the period
            // defaults to a day, because that is what a metered connection is
            // billed on.
            "cap" => {
                let raw = tokens.next().ok_or_else(|| ConfigError::BadValue {
                    key: "limit.cap".to_owned(),
                    value: String::new(),
                })?;
                let (size, mut period_word) = match raw.split_once('/') {
                    Some((sz, p)) => (sz, Some(p.to_owned())),
                    None => (raw, None),
                };
                let bytes = parse_size(size).ok_or_else(|| ConfigError::BadValue {
                    key: "limit.cap".to_owned(),
                    value: raw.to_owned(),
                })?;
                if period_word.is_none() {
                    let connective = tokens.peek().map(|t| t.to_ascii_lowercase());
                    if matches!(connective.as_deref(), Some("per" | "a" | "each")) {
                        tokens.next();
                    }
                    if tokens.peek().is_some_and(|t| CapPeriod::parse(t).is_some()) {
                        period_word = tokens.next().map(str::to_owned);
                    }
                }
                let period = match period_word {
                    Some(w) => CapPeriod::parse(&w).ok_or_else(|| ConfigError::BadValue {
                        key: "limit.cap".to_owned(),
                        value: w,
                    })?,
                    None => CapPeriod::default(),
                };
                limit.cap = Some(Cap::new(bytes, period));
            }
            // `schedule 08:00-18:00` (a limit that only bites during work
            // hours) and `schedule 22:00-06:00` (overnight, wrapping midnight).
            "schedule" | "window" => {
                let v = tokens.next().ok_or_else(|| ConfigError::BadValue {
                    key: "limit.schedule".to_owned(),
                    value: String::new(),
                })?;
                limit.window = Some(Window::parse(v).ok_or_else(|| ConfigError::BadValue {
                    key: "limit.schedule".to_owned(),
                    value: v.to_owned(),
                })?);
            }
            // `per-flow` is a bare token; `scope flow` is the same thing spelled
            // with an argument, because both read naturally in a config file.
            "per-flow" | "perflow" => limit.scope = LimitScope::Flow,
            "scope" => {
                let v = tokens.next().ok_or_else(|| ConfigError::BadValue {
                    key: "limit.scope".to_owned(),
                    value: String::new(),
                })?;
                limit.scope = LimitScope::parse(v).ok_or_else(|| ConfigError::BadValue {
                    key: "limit.scope".to_owned(),
                    value: v.to_owned(),
                })?;
            }
            "process" | "shared" => limit.scope = LimitScope::Process,
            other => {
                return Err(ConfigError::UnknownParam(other.to_owned()));
            }
        }
    }
    Ok(limit)
}

fn parse_u64(v: &str) -> Option<u64> {
    v.trim().parse().ok()
}

const UNITS: [(&str, u64); 14] = [
    ("gbit", 1_000_000_000 / 8),
    ("gbps", 1_000_000_000 / 8),
    ("mbit", 1_000_000 / 8),
    ("mbps", 1_000_000 / 8),
    ("kbit", 1_000 / 8),
    ("kbps", 1_000 / 8),
    ("bps", 1),
    ("gb", 1_000_000_000),
    ("mb", 1_000_000),
    ("kb", 1_000),
    ("b", 1),
    ("g", 1_000_000_000),
    ("m", 1_000_000),
    ("k", 1_000),
];

/// Parse a rate into **bytes per second**: `8mbit`, `20mbps`, `1.5mbit`, `512kb`.
pub fn parse_rate(v: &str) -> Option<u64> {
    let (num, mult) = parse_with_unit(v)?;
    Some(mult_bps(num, mult))
}

fn mult_bps(num: f64, mult: u64) -> u64 {
    // Bit units in `UNITS` are already converted to bytes/s.
    (num * mult as f64) as u64
}

/// Parse a byte count: `64kb`, `1mb`, `1500`, `1.5mb`.
pub fn parse_size(v: &str) -> Option<u64> {
    let (num, mult) = parse_with_unit(v)?;
    Some((num * mult as f64) as u64)
}

/// Parse a duration into milliseconds: `500ms`, `2s`, `1.5s`, `100`.
pub fn parse_duration_ms(v: &str) -> Option<u64> {
    let t = v.trim().to_ascii_lowercase();
    if let Some(rest) = t.strip_suffix("ms") {
        return rest.trim().parse::<f64>().ok().map(|f| f as u64);
    }
    if let Some(rest) = t.strip_suffix('s') {
        return rest.trim().parse::<f64>().ok().map(|f| (f * 1000.0) as u64);
    }
    t.parse::<u64>().ok()
}

fn parse_with_unit(v: &str) -> Option<(f64, u64)> {
    let t = v.trim().to_ascii_lowercase().replace(' ', "");
    for (suffix, mult) in UNITS {
        if let Some(rest) = t.strip_suffix(suffix) {
            let num: f64 = rest.parse().ok()?;
            return Some((num, mult));
        }
    }
    let num: f64 = t.parse().ok()?;
    Some((num, 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rates() {
        assert_eq!(parse_rate("8mbit"), Some(1_000_000));
        assert_eq!(parse_rate("1kbit"), Some(125));
        assert_eq!(parse_rate("10mbps"), Some(1_250_000));
        assert_eq!(parse_rate("1.5mbit"), Some(187_500));
        assert_eq!(parse_rate("800000"), Some(800_000));
    }

    #[test]
    fn parses_sizes_and_durations() {
        assert_eq!(parse_size("64kb"), Some(64_000));
        assert_eq!(parse_size("1.5mb"), Some(1_500_000));
        assert_eq!(parse_duration_ms("500ms"), Some(500));
        assert_eq!(parse_duration_ms("2s"), Some(2_000));
        assert_eq!(parse_duration_ms("100"), Some(100));
    }

    #[test]
    fn parses_full_config() {
        let text = "\
# example
param queue-length = 512
param queue-time = 250ms
limit chrome.exe = 8mbit burst 64kb policy shape
limit steam.exe = 20mbit policy drop
rule limit=chrome.exe : tcp
";
        let (cfg, rules) = Config::parse(text).unwrap();
        assert_eq!(cfg.queue_length, 512);
        assert_eq!(cfg.queue_time_ms, 250);
        assert_eq!(cfg.limits.len(), 2);
        assert_eq!(cfg.limit("chrome.exe").unwrap().rate_bps, 1_000_000);
        assert_eq!(
            cfg.limit("steam.exe").unwrap().policy,
            OverLimitPolicy::Drop
        );
        assert_eq!(rules.len(), 1);
    }

    #[test]
    fn round_trips_params() {
        let cfg = Config::default();
        let text = cfg.to_params_text();
        let (again, _) = Config::parse(&text).unwrap();
        assert_eq!(cfg.queue_length, again.queue_length);
        assert_eq!(cfg.max_retain_ms, again.max_retain_ms);
    }

    #[test]
    fn rejects_unknown_param() {
        assert!(matches!(
            Config::default().set_param("nope", "1"),
            Err(ConfigError::UnknownParam(_))
        ));
    }

    #[test]
    fn validate_rejects_zero_rate() {
        assert!(Limits::new("x").rate(0).validate().is_err());
        assert!(Limits::new("x").bits(8_000_000).validate().is_ok());
    }

    #[test]
    fn parses_per_flow_scope_two_ways() {
        let (cfg, _) = Config::parse(
            "limit browser.exe = 8mbit per-flow\n\
             limit backup.exe  = 2mbit scope flow burst 8kb\n\
             limit plain.exe   = 1mbit\n",
        )
        .unwrap();
        assert_eq!(
            cfg.limit("browser.exe").unwrap().scope,
            LimitScope::Flow,
            "the bare `per-flow` token must set the scope"
        );
        assert_eq!(cfg.limit("backup.exe").unwrap().scope, LimitScope::Flow);
        // The rest of the line still parses after the scope token.
        assert_eq!(cfg.limit("backup.exe").unwrap().burst_bytes, 8_000);
        // Defaulting is not accidental.
        assert_eq!(cfg.limit("plain.exe").unwrap().scope, LimitScope::Process);
    }

    #[test]
    fn rejects_a_bad_scope_value() {
        let err = Config::parse("limit x.exe = 1mbit scope banana\n").unwrap_err();
        assert!(matches!(err, ConfigError::BadValue { .. }), "{err:?}");
    }

    #[test]
    fn parses_caps_in_every_spelling() {
        let (cfg, _) = Config::parse(
            "limit a.exe = 1mbit cap 50gb/day\n\
             limit b.exe = 1mbit cap 2mb per month\n\
             limit c.exe = 1mbit cap 1gb\n",
        )
        .unwrap();
        let a = cfg.limit("a.exe").unwrap().cap.unwrap();
        assert_eq!(a.bytes, 50_000_000_000);
        assert_eq!(a.period, CapPeriod::Day);
        let b = cfg.limit("b.exe").unwrap().cap.unwrap();
        assert_eq!(b.bytes, 2_000_000);
        assert_eq!(b.period, CapPeriod::Month);
        // No period given: a day, because that is what is billed.
        let c = cfg.limit("c.exe").unwrap().cap.unwrap();
        assert_eq!(c.bytes, 1_000_000_000);
        assert_eq!(c.period, CapPeriod::Day);
    }

    #[test]
    fn parses_schedules_and_rejects_empty_ones() {
        let (cfg, _) = Config::parse("limit a.exe = 1mbit schedule 08:00-18:00\n").unwrap();
        let w = cfg.limit("a.exe").unwrap().window.unwrap();
        assert_eq!((w.start_min, w.end_min), (8 * 60, 18 * 60));

        // Bare hours are accepted, and a window may cross midnight.
        let (cfg, _) = Config::parse("limit b.exe = 1mbit schedule 22-6\n").unwrap();
        let w = cfg.limit("b.exe").unwrap().window.unwrap();
        assert!(w.wraps());
        assert_eq!(w.to_string(), "22:00-06:00");

        // A zero-length window and an impossible clock are typos, not defaults.
        let bad = [
            "limit c.exe = 1mbit schedule 09:00-09:00\n",
            "limit c.exe = 1mbit schedule 25:00-26:00\n",
            "limit c.exe = 1mbit schedule nonsense\n",
        ];
        for text in bad {
            assert!(Config::parse(text).is_err(), "accepted {text:?}");
        }
    }

    #[test]
    fn window_membership_handles_both_sides_of_midnight() {
        let day = Window::parse("08:00-18:00").unwrap();
        assert!(day.contains(8 * 60));
        assert!(day.contains(18 * 60 - 1));
        assert!(!day.contains(18 * 60), "the end is exclusive");
        assert!(!day.contains(7 * 60 + 59));

        let night = Window::parse("22:00-06:00").unwrap();
        assert!(night.contains(22 * 60));
        assert!(night.contains(23 * 60 + 30));
        assert!(night.contains(0));
        assert!(night.contains(5 * 60 + 59));
        assert!(!night.contains(6 * 60));
        assert!(!night.contains(12 * 60));
    }

    #[test]
    fn rejects_a_zero_or_malformed_cap() {
        // Zero bytes would drop everything forever.
        assert!(Config::parse("limit a.exe = 1mbit cap 0/day\n").is_err());
        // A period nobody implements must not silently become "day".
        assert!(Config::parse("limit a.exe = 1mbit cap 5gb/week\n").is_err());
        // A cap with no value at all is a typo, not a default.
        assert!(Config::parse("limit a.exe = 1mbit cap\n").is_err());
    }

    #[test]
    fn scope_spellings_round_trip() {
        for scope in [LimitScope::Process, LimitScope::Flow] {
            assert_eq!(LimitScope::parse(scope.as_str()), Some(scope));
            assert_eq!(LimitScope::parse(scope.as_token()), Some(scope));
            let (cfg, _) =
                Config::parse(&format!("limit a.exe = 1mbit {}\n", scope.as_token())).unwrap();
            assert_eq!(cfg.limit("a.exe").unwrap().scope, scope);
        }
    }
}
