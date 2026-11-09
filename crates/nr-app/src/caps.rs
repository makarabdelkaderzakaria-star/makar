//! On-disk counters for data caps.
//!
//! A cap that forgets how much was used when the daemon restarts is not a cap,
//! it is a speed bump: restart NetRocket and you get your budget back. The file
//! this module maintains is the smallest thing that fixes that — a handful of
//! lines, next to the configuration file:
//!
//! ```text
//! # netrocket caps v1
//! # name<TAB>used-bytes<TAB>period-stamp
//! backup.exe<TAB>1834214400<TAB>20766
//! ```
//!
//! The period stamp (`Calendar` day or month index) is stored with the count so
//! a stale counter is *ignored* rather than restored: a file from yesterday
//! cannot charge today's budget, even if the daemon was down across midnight.
//!
//! Nothing here is trusted: a missing file is normal, a corrupt line is skipped,
//! and a write goes through a temporary file so a crash mid-save cannot leave a
//! half-written counter behind.
//!
//! Only the Windows daemon has a long-running process to persist from, so on
//! other platforms the persistence helpers below look unused to rustc; the tests
//! still exercise the format everywhere.

#![cfg_attr(not(windows), allow(dead_code))]

use nr_core::{Calendar, CapUsage, Engine};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

/// Header written at the top of every counter file.
pub const HEADER: &str = "# netrocket caps v1";

/// Path of the counter file for a configuration file.
///
/// `netrocket.conf` -> `netrocket.conf.caps`. Deliberately *not* inside the
/// configuration file: the config is user-edited and hand-formatted, and a
/// counter that rewrites itself every minute would fight the editor.
#[must_use]
pub fn path_for(config: &Path) -> PathBuf {
    with_suffix(config, ".caps")
}

/// `path` with `suffix` appended to the whole path (`netrocket.conf.caps`).
fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(suffix);
    PathBuf::from(s)
}

/// Load counters into `engine`.
///
/// Returns the number of restored rows, which is what `run` logs: "restored 2
/// caps" is the difference between a feature that works and one that silently
/// doubles a metered bill.
pub fn load_into(engine: &mut Engine<8192>, path: &Path) -> usize {
    let Ok(text) = fs::read_to_string(path) else {
        return 0;
    };
    let mut restored = 0;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split('\t');
        let (Some(name), Some(used), Some(stamp)) = (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let (Ok(used), Ok(stamp)) = (used.parse::<u64>(), stamp.parse::<u32>()) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        if engine.restore_cap_usage(name, used, stamp) {
            restored += 1;
        }
    }
    restored
}

/// Render the current usage as a counter file.
#[must_use]
pub fn render(usage: &[CapUsage]) -> String {
    let mut out = String::with_capacity(64 + usage.len() * 40);
    out.push_str(HEADER);
    out.push('\n');
    out.push_str("# name\tused-bytes\tperiod-stamp\n");
    for u in usage {
        // Tab-separated: limit names contain dots and spaces but never a tab,
        // and a counter file that needs quoting is a counter file with bugs.
        let _ = writeln!(out, "{}\t{}\t{}", u.name, u.used, u.stamp);
    }
    out
}

/// Save the engine's current usage for `calendar`.
///
/// Writes through a temporary file and renames it, so a crash cannot leave a
/// truncated counter that undercharges the user.
pub fn save(engine: &Engine<8192>, path: &Path) -> Result<(), String> {
    let usage = engine.cap_usage();
    if usage.is_empty() {
        return Ok(());
    }
    let text = render(&usage);
    let tmp = with_suffix(path, ".tmp");
    write_atomically(&tmp, path, text.as_bytes())
}

/// Write `bytes` to `tmp`, flush it to disk, then rename it over `path`.
fn write_atomically(tmp: &Path, path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write as _;

    let created = fs::File::create(tmp);
    let mut file = created.map_err(|e| format!("cannot create {}: {e}", tmp.display()))?;

    if let Err(e) = file.write_all(bytes) {
        let _ = fs::remove_file(tmp);
        return Err(format!("cannot write {}: {e}", tmp.display()));
    }
    if let Err(e) = file.sync_all() {
        let _ = fs::remove_file(tmp);
        return Err(format!("cannot flush {}: {e}", tmp.display()));
    }
    drop(file);

    if let Err(e) = fs::rename(tmp, path) {
        let _ = fs::remove_file(tmp);
        return Err(format!("cannot replace {}: {e}", path.display()));
    }
    Ok(())
}

/// Current UTC calendar, for [`nr_core::Engine::set_calendar`].
///
/// Seconds since the Unix epoch, clamped at the epoch: a machine whose clock is
/// set to 1969 gets day 0 rather than a panic, and the counter file's stamps
/// make the mistake visible instead of silently resetting a cap forever.
#[must_use]
pub fn utc_now() -> Calendar {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    Calendar::from_unix_secs(secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nr_core::{CapPeriod, Config, Direction};

    /// A config with one capped limit, parsed from the user-facing syntax.
    fn capped_config() -> Config {
        let text = "limit backup.exe = 64mbit cap 1mb/day\n";
        let (cfg, _) = Config::parse(text).unwrap();
        cfg
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("nr-caps-{tag}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn counter_path_sits_next_to_the_config() {
        let p = path_for(Path::new("C:/netrocket/netrocket.conf"));
        assert_eq!(p, PathBuf::from("C:/netrocket/netrocket.conf.caps"));
    }

    #[test]
    fn round_trips_through_the_file() {
        let dir = temp_dir("roundtrip");
        let path = dir.join("netrocket.conf.caps");

        // Charge the counter by pushing a packet through the engine, so the
        // number written to disk is the number the packet path produced.
        let rules = vec!["limit=backup.exe : tcp dport 443".to_owned()];
        let cfg = capped_config();
        let (_, compiled) = Engine::<8192>::compile_rules(&rules, &cfg.limits).unwrap();
        let mut e = Engine::<8192>::new(cfg);
        e.set_rules(compiled);
        e.set_calendar(Calendar::from_day_index(20_766));
        let frame = nr_core::frame::tcp_v4([10, 0, 0, 1], 1234, [1, 1, 1, 1], 443, &[0; 500]);
        let out = e.process(&frame, Direction::Outbound, 0, 0, 0, 0, 0);
        assert!(out.is_send_now(), "the first packet fits under a fresh cap");
        save(&e, &path).unwrap();

        // A different engine, same clock, restores the count.
        let mut b = Engine::<8192>::new(capped_config());
        b.set_calendar(Calendar::from_day_index(20_766));
        assert_eq!(load_into(&mut b, &path), 1);
        let usage = b.cap_usage();
        assert_eq!(usage.len(), 1);
        assert!(usage[0].used > 0, "the counter was not restored");
        assert_eq!(usage[0].stamp, 20_766);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_counter_from_another_day_is_ignored() {
        let dir = temp_dir("stale");
        let path = dir.join("c.caps");
        fs::write(&path, format!("{HEADER}\nbackup.exe\t900000\t100\n")).unwrap();

        let mut e = Engine::<8192>::new(capped_config());
        e.set_calendar(Calendar::from_day_index(20_766));
        load_into(&mut e, &path);
        assert_eq!(
            e.cap_usage()[0].used,
            0,
            "yesterday's spend must not be charged to today"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_lines_are_skipped_not_fatal() {
        let dir = temp_dir("corrupt");
        let path = dir.join("c.caps");
        // Empty lines, comments, a non-numeric count and a truncated row.
        let text = format!("{HEADER}\n# c\n\nbackup.exe\tnonsense\t20766\nbackup.exe\t12\n");
        fs::write(&path, text).unwrap();

        let mut e = Engine::<8192>::new(capped_config());
        e.set_calendar(Calendar::from_day_index(20_766));
        assert_eq!(
            load_into(&mut e, &path),
            0,
            "nothing in that text is usable"
        );
        assert_eq!(e.cap_usage()[0].used, 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_file_is_not_an_error() {
        let mut e = Engine::<8192>::new(capped_config());
        assert_eq!(load_into(&mut e, Path::new("does-not-exist.caps")), 0);
    }

    #[test]
    fn render_is_stable_and_machine_readable() {
        let usage = vec![CapUsage {
            name: "backup.exe".to_owned(),
            used: 42,
            cap: 100,
            period: CapPeriod::Month,
            stamp: 682,
        }];
        let text = render(&usage);
        assert!(text.starts_with(HEADER));
        assert!(text.contains("backup.exe\t42\t682"));
    }
}
