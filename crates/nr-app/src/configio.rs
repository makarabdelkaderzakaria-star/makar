//! Loading, writing and explaining configuration files.
//!
//! Persistence is deliberately boring but *careful*: write to
//! `path.tmp`, `sync_all()`, then `rename`. The original used temp+`File.Move`,
//! which is atomic against a crash but never flushed, so a power loss could
//! leave a truncated file behind. One extra `fsync` per save is free at this
//! frequency and removes that class of bug.

use nr_core::config::Config;
use nr_core::rules::CompiledRules;
use nr_core::Engine;
use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

/// A loaded, validated configuration.
#[derive(Debug)]
pub struct Loaded {
    /// Validated parameters and limits.
    pub config: Config,
    /// Compiled rules, ready for the engine.
    pub rules: CompiledRules,
    /// Raw rule text, in order.
    pub rule_text: Vec<String>,
}

/// Read and validate `path`.
pub fn load(path: &Path) -> Result<Loaded, String> {
    let text =
        fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let (config, rule_text) =
        Config::parse(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    config
        .validate()
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let (_, rules) = Engine::<8192>::compile_rules(&rule_text, &config.limits)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(Loaded {
        config,
        rules,
        rule_text,
    })
}

/// Load `path`, or a default configuration when the file does not exist.
pub fn load_or_default(path: &Path) -> Result<Loaded, String> {
    match fs::metadata(path) {
        Ok(_) => load(path),
        Err(e) if e.kind() == ErrorKind::NotFound => {
            let config = Config::default();
            let (_, rules) =
                Engine::<8192>::compile_rules(&[], &config.limits).map_err(|e| e.to_string())?;
            Ok(Loaded {
                config,
                rules,
                rule_text: Vec::new(),
            })
        }
        Err(e) => Err(format!("cannot stat {}: {e}", path.display())),
    }
}

/// The file written by `netrocket init`.
#[must_use]
pub fn template() -> String {
    let mut s = String::new();
    s.push_str(TEMPLATE);
    s
}

/// The commented configuration written by `netrocket init`.
pub const TEMPLATE: &str = r#"# netrocket configuration
# ---------------------------------------------------------------------------
# Rates are written the way you would say them: 8mbit, 500kbit, 2mbps.
# Bursts and budgets take byte units: 64kb, 1mb.
# Everything after a '#' is a comment.
# ---------------------------------------------------------------------------

# --- driver queue (WinDivert) ---------------------------------------------
# A shorter queue means less standing delay. The driver default is 4096
# packets / 2000 ms, which is a bufferbloat factory for a shaper.
param queue-length = 1024
param queue-time = 400ms
param queue-size = 1mb

# --- our own retention buffer ---------------------------------------------
# How many bytes of packets we may hold while waiting for a rate to allow
# them, and for how long. 250 ms is deliberately below the smallest plausible
# TCP retransmission timeout, so nothing we hold is ever retransmitted.
param retain-budget = 2mb
param max-retain = 250ms
#
# CoDel: keep the *standing* queue short, not just the average. When the
# packets we hold have waited more than the target for a whole interval, drop
# the ones that would be late instead of delivering them late. Off by default
# (0); 5ms is the usual target and 100ms the usual interval.
# param codel = 5ms
# param codel-interval = 100ms

# --- housekeeping ---------------------------------------------------------
param flow-idle = 120s
param identity-ttl = 30s
param batch-max = 64

# --- limits ---------------------------------------------------------------
# limit <name> = <rate> [burst <bytes>] [policy shape|drop|drop-inbound] [per-flow]
#                 [cap <bytes>/day|<bytes>/month] [schedule HH:MM-HH:MM]
#
# policy shape         delay packets until they fit (no retransmissions)
# policy drop          drop over-limit packets (TCP retransmits: wasteful)
# policy drop-inbound  drop inbound packets instead (the peer slows down)
# policy ecn           mark the packet CE and forward it, but only when the
#                      transport negotiated ECN; anything else is shaped. The
#                      sender halves its window without a retransmission.
#
# per-flow             one bucket per connection instead of one per process.
#                      A browser with one tab on a 4K stream no longer starves
#                      its own DNS lookups. `scope process` is the default.
#
# schedule <window>    only enforce the limit inside this UTC window, e.g.
#                      `schedule 08:00-18:00`, or `schedule 22:00-06:00` for
#                      overnight. Outside it the limit does not exist: nothing
#                      is shaped and no cap is charged.
#
# cap <bytes>/<period> a byte budget for the limit, reset at 00:00 UTC every
#                      day or on the first of the month. Bytes count in both
#                      directions. When it is spent, matching packets are
#                      dropped until the period rolls over; the counter is
#                      kept in <config>.caps so a restart does not refund it.
#
limit chrome.exe  = 8mbit   burst 64kb policy ecn
limit steam.exe   = 20mbit  burst 256kb schedule 08:00-18:00
limit backup.exe  = 2mbit   burst 32kb policy drop cap 20gb/month
limit browser.exe = 8mbit   burst 64kb per-flow

# --- rules ---------------------------------------------------------------
# First match wins. An empty rule list means "count only, shape nothing".
#
# rule limit=<name> : <match>
# rule block        : <match>
# rule allow        : all
#
# match grammar: [tcp|udp|icmp] [in|out] [sport N[-M]] [dport N[-M]]
#                [src A.B.C.D/len] [dst A.B.C.D/len] [proc name.exe]
# `proc <name>` is what makes a limit belong to ONE process. Without it a limit
# is a shared bucket: several processes matching the same rule share its rate.
rule limit=chrome.exe  : proc chrome.exe
rule limit=steam.exe   : proc steam.exe
rule limit=backup.exe  : proc backup.exe
rule limit=browser.exe : proc browser.exe
"#;

/// Write `text` to `path` atomically (temp file, fsync, rename).
pub fn save_atomic(path: &Path, text: &str) -> Result<(), String> {
    let tmp = temp_path(path);
    {
        let mut f =
            fs::File::create(&tmp).map_err(|e| format!("cannot create {}: {e}", tmp.display()))?;
        f.write_all(text.as_bytes())
            .map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
        f.sync_all()
            .map_err(|e| format!("cannot flush {}: {e}", tmp.display()))?;
    }
    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!("cannot replace {}: {e}", path.display())
    })
}

fn temp_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".tmp");
    PathBuf::from(s)
}

/// Human-readable dump of what the engine will actually do. This is the
/// answer to "why is nothing being limited?" — it shows the compiled rules,
/// including the ones whose process name never matched anything.
#[must_use]
pub fn lint(loaded: &Loaded) -> String {
    let mut s = String::new();
    s.push_str("limits\n");
    if loaded.config.limits.is_empty() {
        s.push_str("  (none) — traffic is only counted, never shaped\n");
    }
    for l in &loaded.config.limits {
        let mut line = format!(
            "  {:<16} {:>10}  burst {:>8}  policy {:<12} scope {}",
            l.name,
            nr_core::stats::human_bps(l.rate_bps),
            nr_core::stats::human_bytes(l.burst_bytes),
            l.policy.as_str(),
            l.scope.as_str()
        );
        if let Some(cap) = l.cap {
            line.push_str(&format!(
                "  cap {}/{}",
                nr_core::stats::human_bytes(cap.bytes),
                cap.period.as_str()
            ));
        }
        if let Some(window) = l.window {
            line.push_str(&format!("  schedule {window}"));
        }
        line.push('\n');
        s.push_str(&line);
    }

    s.push_str("\nrules (first match wins)\n");
    if loaded.rule_text.is_empty() {
        s.push_str("  (none) — everything is forwarded untouched\n");
    }
    for (i, text) in loaded.rule_text.iter().enumerate() {
        s.push_str(&format!("  {:>2}. {}\n", i + 1, text));
    }

    s.push_str("\ncompiled predicates\n");
    for (i, r) in loaded.rules.rules().iter().enumerate() {
        let action = match r.action {
            nr_core::Action::Allow => "allow".to_owned(),
            nr_core::Action::Block => "block".to_owned(),
            nr_core::Action::Limit(li) => format!(
                "limit={}",
                loaded
                    .config
                    .limits
                    .get(li as usize)
                    .map_or("?", |l| l.name.as_str())
            ),
            nr_core::Action::Pass => "pass".to_owned(),
        };
        let mut needs = Vec::new();
        if r.need.contains(nr_core::rules::Predicates::PROC) {
            needs.push(
                loaded
                    .rules
                    .names()
                    .get(r.proc_id as usize)
                    .cloned()
                    .unwrap_or_else(|| "?".to_owned()),
            );
        }
        if r.need.contains(nr_core::rules::Predicates::PROTO) {
            needs.push(
                ["tcp", "udp", "other", "any"]
                    .get(r.proto as usize)
                    .unwrap_or(&"any")
                    .to_string(),
            );
        }
        if r.need.contains(nr_core::rules::Predicates::DPORT) {
            needs.push(format!("dport {}-{}", r.dport.lo, r.dport.hi));
        }
        if r.need.contains(nr_core::rules::Predicates::SPORT) {
            needs.push(format!("sport {}-{}", r.sport.lo, r.sport.hi));
        }
        if r.need.contains(nr_core::rules::Predicates::DST) {
            needs.push("dst prefix".to_owned());
        }
        if r.need.contains(nr_core::rules::Predicates::SRC) {
            needs.push("src prefix".to_owned());
        }
        if r.need.contains(nr_core::rules::Predicates::DIR) {
            needs.push(if r.dir == 0 {
                "out".to_owned()
            } else {
                "in".to_owned()
            });
        }
        s.push_str(&format!(
            "  {:>2}. {:<14} need: {}\n",
            i + 1,
            action,
            if needs.is_empty() {
                "everything".to_owned()
            } else {
                needs.join(", ")
            }
        ));
    }

    s.push_str("\nengine parameters\n");
    let c = &loaded.config;
    s.push_str(&format!(
        "  queue           {} packets / {} ms / {}\n",
        c.queue_length,
        c.queue_time_ms,
        nr_core::stats::human_bytes(c.queue_size)
    ));
    s.push_str(&format!(
        "  retention       {} budget, {} max wait\n",
        nr_core::stats::human_bytes(c.retain_budget_bytes),
        c.max_retain_ms
    ));
    s.push_str(&format!("  flow idle       {} ms\n", c.flow_idle_ms));
    s.push_str(&format!("  identity ttl    {} ms\n", c.identity_ttl_ms));
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_round_trips() {
        let text = template();
        let (cfg, rules) = Config::parse(&text).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.limits.len(), 4);
        assert_eq!(rules.len(), 4);
        let (_, compiled) = Engine::<8192>::compile_rules(&rules, &cfg.limits).unwrap();
        assert_eq!(compiled.len(), 4);
        assert_eq!(
            cfg.limit("browser.exe").unwrap().scope,
            nr_core::LimitScope::Flow,
            "the template must keep demonstrating per-flow scope"
        );
    }

    #[test]
    fn atomic_save_and_reload() {
        let dir = std::env::temp_dir().join("nr-test-configio");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("netrocket.conf");
        save_atomic(&path, &template()).unwrap();
        let loaded = load(&path).unwrap();
        assert_eq!(loaded.config.limits.len(), 4);
        assert!(!dir.join("netrocket.conf.tmp").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_file_falls_back_to_defaults() {
        let path = std::env::temp_dir().join("nr-definitely-not-here.conf");
        let loaded = load_or_default(&path).unwrap();
        assert!(loaded.config.limits.is_empty());
        assert!(loaded.rules.is_empty());
    }

    #[test]
    fn lint_mentions_limits_and_rules() {
        let dir = std::env::temp_dir().join("nr-test-lint");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("c.conf");
        save_atomic(&path, &template()).unwrap();
        let loaded = load(&path).unwrap();
        let out = lint(&loaded);
        assert!(out.contains("chrome.exe"));
        assert!(out.contains("first match wins"));
        assert!(out.contains("Mbit/s"));
        assert!(
            out.contains("scope per-flow"),
            "lint must show the scope:\n{out}"
        );
        assert!(
            out.contains("cap 20.00 GB/month"),
            "lint must show the cap and its period:\n{out}"
        );
        assert!(
            out.contains("schedule 08:00-18:00"),
            "lint must show the schedule:\n{out}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn broken_file_is_reported_with_its_path() {
        let dir = std::env::temp_dir().join("nr-test-broken");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("bad.conf");
        save_atomic(&path, "rule limit=nope : tcp\n").unwrap();
        let err = load(&path).unwrap_err();
        assert!(err.contains("bad.conf"), "{err}");
        let _ = fs::remove_dir_all(&dir);
    }
}
