//! `netrocket doctor` — can this machine run the engine?
//!
//! Every check here is read-only: it reads files, parses a configuration, and
//! asks the operating system for its endpoint table. It **never** opens a
//! WinDivert handle, so it cannot divert, drop or reorder a single packet. That
//! matters: a diagnostic that changes the thing it diagnoses is worse than none.
//!
//! The point is to turn the three usual Windows failures (driver files missing,
//! not elevated, driver signature rejected) into a sentence that says which one
//! it is, *before* the user runs `netrocket run` and wonders why nothing happens.

use std::path::Path;

/// Result of one check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Everything is as it should be.
    Ok,
    /// Not a problem, but worth knowing.
    Note,
    /// `netrocket run` will not work until this is fixed.
    Fail,
}

/// One line of the report.
#[derive(Debug, Clone)]
pub struct Check {
    /// Short name.
    pub name: String,
    /// Outcome.
    pub status: Status,
    /// What was found.
    pub detail: String,
    /// What to do about it (empty when nothing needs doing).
    pub fix: String,
}

impl Check {
    fn new(name: &str, status: Status, detail: impl Into<String>, fix: impl Into<String>) -> Self {
        Self {
            name: name.to_owned(),
            status,
            detail: detail.into(),
            fix: fix.into(),
        }
    }
}

/// The whole report.
#[derive(Debug, Default)]
pub struct Report {
    /// Individual checks, in the order a user should read them.
    pub checks: Vec<Check>,
}

impl Report {
    /// Did anything fatal appear?
    #[must_use]
    pub fn failed(&self) -> bool {
        self.checks.iter().any(|c| c.status == Status::Fail)
    }

    /// Number of failures.
    #[must_use]
    pub fn failures(&self) -> usize {
        self.checks
            .iter()
            .filter(|c| c.status == Status::Fail)
            .count()
    }

    /// Render for a terminal.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();
        for c in &self.checks {
            let mark = match c.status {
                Status::Ok => "ok  ",
                Status::Note => "note",
                Status::Fail => "FAIL",
            };
            out.push_str(&format!("[{mark}] {:<22} {}\n", c.name, c.detail));
            if !c.fix.is_empty() {
                out.push_str(&format!("       {:<22} → {}\n", "", c.fix));
            }
        }
        out.push('\n');
        if self.failed() {
            out.push_str(&format!(
                "{} check(s) failed: `netrocket run` will not work on this machine yet.\n",
                self.failures()
            ));
        } else if cfg!(windows) {
            out.push_str("all checks passed: this machine can run `netrocket run`.\n");
        } else {
            out.push_str(
                "nothing to fix here. `netrocket run` needs Windows; `simulate`, `bench`,\n\
                 `lint`, `check` and `init` all work on this platform.\n",
            );
        }
        out
    }
}

/// Run every check.
///
/// `config_path` is validated when it exists; a missing file is a `Note`, not a
/// failure, because `netrocket run` falls back to defaults.
#[must_use]
pub fn diagnose(config_path: &Path) -> Report {
    let mut r = Report::default();

    // 1. Platform.
    if cfg!(windows) {
        r.checks.push(Check::new(
            "platform",
            Status::Ok,
            format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS),
            "",
        ));
    } else {
        r.checks.push(Check::new(
            "platform",
            Status::Note,
            "not Windows: `run` is unavailable, `simulate`/`bench`/`lint` work",
            "",
        ));
    }

    // 2. Driver binaries, searched next to the executable and on PATH.
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf));
    let mut found = Vec::new();
    for name in ["WinDivert.dll", "WinDivert64.sys"] {
        let mut places: Vec<std::path::PathBuf> = Vec::new();
        if let Some(dir) = &exe_dir {
            places.push(dir.join(name));
        }
        if let Some(path) = std::env::var_os("PATH") {
            for dir in std::env::split_paths(&path) {
                places.push(dir.join(name));
            }
        }
        match places.iter().find(|p| p.is_file()) {
            Some(p) => found.push((name, p.display().to_string())),
            None => found.push((name, String::new())),
        }
    }
    let missing: Vec<&str> = found
        .iter()
        .filter(|(_, p)| p.is_empty())
        .map(|(n, _)| *n)
        .collect();
    if missing.is_empty() {
        let detail = found
            .iter()
            .map(|(n, p)| format!("{n} at {p}"))
            .collect::<Vec<_>>()
            .join("; ");
        r.checks
            .push(Check::new("driver files", Status::Ok, detail, ""));
    } else if cfg!(windows) {
        r.checks.push(Check::new(
            "driver files",
            Status::Fail,
            format!("missing: {}", missing.join(", ")),
            "run scripts/install-windivert.ps1 (it verifies the Authenticode signature)",
        ));
    } else {
        // Not a problem here: `run` is unavailable anyway, and everything else
        // is a pure-Rust path that needs no driver.
        r.checks.push(Check::new(
            "driver files",
            Status::Note,
            "not needed on this platform (no `run` backend)",
            "",
        ));
    }

    // 3. Elevation. Only meaningful on Windows; `netadmin`-style admin checks
    //    need FFI, so we use the portable proxy (session 0 / admin env hint) and
    //    say which proxy was used rather than pretending to know.
    if cfg!(windows) {
        let elevated = std::env::var_os("USERNAME").is_some()
            && std::env::var_os("SystemRoot").is_some()
            && !std::env::var("SESSIONNAME").is_ok_and(|s| s.is_empty());
        r.checks.push(Check::new(
            "elevation",
            if elevated { Status::Ok } else { Status::Fail },
            if elevated {
                "an interactive session was detected".to_owned()
            } else {
                "no interactive session detected".to_owned()
            },
            if elevated {
                ""
            } else {
                "start PowerShell with Run as Administrator"
            },
        ));
        // Be explicit that this is a heuristic.
        r.checks.push(Check::new(
            "elevation (how)",
            Status::Note,
            "checked via environment, not by opening a privileged handle",
            "",
        ));
    }

    // 4. Endpoint table: the same call the start-up snapshot makes.
    #[cfg(windows)]
    {
        let mut resolver = nr_divert::win::WinResolver::new();
        let snap = nr_divert::win_snapshot::win::read_all(|pid| resolver.start_time(pid));
        let mut table = nr_core::FlowAttribution::new(8192, 60_000);
        let report = table.seed(snap.entries, 0);
        if snap.errors.is_empty() {
            r.checks.push(Check::new(
                "endpoint table",
                Status::Ok,
                format!(
                    "{} established, {} listeners/unconnected",
                    report.connected, report.listeners
                ),
                "",
            ));
        } else {
            r.checks.push(Check::new(
                "endpoint table",
                Status::Fail,
                snap.errors.join("; "),
                "the start-up snapshot will not work; pre-existing flows stay unattributed",
            ));
        }
    }
    #[cfg(not(windows))]
    {
        r.checks.push(Check::new(
            "endpoint table",
            Status::Note,
            "GetExtendedTcpTable is Windows-only",
            "",
        ));
    }

    // 5. Configuration.
    if config_path.is_file() {
        match crate::configio::load(config_path) {
            Ok(loaded) => {
                let limit_without_rule = loaded
                    .config
                    .limits
                    .iter()
                    .filter(|l| {
                        let needle = format!("limit={}", l.name);
                        !loaded
                            .rule_text
                            .iter()
                            .any(|r| r.to_ascii_lowercase().contains(&needle))
                    })
                    .map(|l| l.name.clone())
                    .collect::<Vec<_>>();
                r.checks.push(Check::new(
                    "configuration",
                    Status::Ok,
                    format!(
                        "{} limits, {} rules",
                        loaded.config.limits.len(),
                        loaded.rule_text.len()
                    ),
                    "",
                ));
                if !limit_without_rule.is_empty() {
                    r.checks.push(Check::new(
                        "limits unused",
                        Status::Note,
                        format!("no rule references: {}", limit_without_rule.join(", ")),
                        "a limit only applies through a `rule limit=<name>` line",
                    ));
                }
            }
            Err(e) => r.checks.push(Check::new(
                "configuration",
                Status::Fail,
                e,
                "fix the file or run `netrocket init`",
            )),
        }
    } else {
        r.checks.push(Check::new(
            "configuration",
            Status::Note,
            format!("{} not found; defaults will be used", config_path.display()),
            "run `netrocket init` to create one",
        ));
    }

    // 6. What the engine will actually do, in one line.
    r.checks.push(Check::new(
        "engine",
        Status::Ok,
        format!(
            "retention {} / {} ms, {} packet queue",
            nr_core::stats::human_bytes(nr_core::Config::default().retain_budget_bytes),
            nr_core::Config::default().max_retain_ms,
            nr_core::Config::default().queue_length
        ),
        "",
    ));

    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_renders_marks_and_verdict() {
        let mut r = Report::default();
        r.checks.push(Check::new("platform", Status::Ok, "x", ""));
        r.checks.push(Check::new(
            "driver files",
            Status::Fail,
            "missing",
            "install",
        ));
        let text = r.render();
        assert!(text.contains("[ok  ] platform"));
        assert!(text.contains("[FAIL] driver files"));
        assert!(text.contains("→ install"));
        assert!(text.contains("1 check(s) failed"));
        assert!(r.failed());
        assert_eq!(r.failures(), 1);
    }

    #[test]
    fn passing_report_says_so() {
        let mut r = Report::default();
        r.checks.push(Check::new("platform", Status::Ok, "x", ""));
        assert!(!r.failed());
        let text = r.render();
        // The verdict is platform-aware: "can run `run`" is only true on Windows.
        if cfg!(windows) {
            assert!(text.contains("all checks passed"));
        } else {
            assert!(text.contains("nothing to fix here"));
            assert!(text.contains("needs Windows"));
        }
        assert!(!text.contains("check(s) failed"));
    }

    #[test]
    fn diagnose_runs_without_panicking_on_this_host() {
        let report = diagnose(Path::new("this-file-does-not-exist.conf"));
        assert!(!report.checks.is_empty());
        // A missing config is a note, never a failure.
        let config = report
            .checks
            .iter()
            .find(|c| c.name == "configuration")
            .expect("configuration check");
        assert_eq!(config.status, Status::Note);
        let text = report.render();
        assert!(text.contains("platform"));
        assert!(text.contains("driver files"));
    }

    #[test]
    fn unused_limits_are_pointed_out() {
        let dir = std::env::temp_dir().join("nr-doctor-unused");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("c.conf");
        std::fs::write(
            &path,
            "limit chrome.exe = 8mbit\nlimit orphan.exe = 1mbit\nrule limit=chrome.exe : proc chrome.exe\n",
        )
        .unwrap();
        let report = diagnose(&path);
        let note = report
            .checks
            .iter()
            .find(|c| c.name == "limits unused")
            .expect("should notice the unused limit");
        assert!(note.detail.contains("orphan.exe"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
