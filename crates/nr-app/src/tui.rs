//! A deliberately tiny status display.
//!
//! No TUI framework: it appends one line per second, which works in every
//! terminal, over SSH, and in a redirected log file. The original shipped a WPF
//! window; that is 40 MB of framework for a table of numbers. Here the whole
//! "UI" is this file.

use nr_core::stats::{human_bps, human_bytes, Delta, Snapshot};

/// One rendered status line.
#[must_use]
pub fn line(snap: &Snapshot, delta: &Delta, elapsed_ms: u64) -> String {
    format!(
        "[{:>6.1}s] {:>5} pps  {:>10}  flows {:<5} held {:>8}  drops {:<6} shaped {}",
        elapsed_ms as f64 / 1000.0,
        delta.pps(),
        human_bps(delta.bytes_per_sec()),
        snap.flows,
        human_bytes(snap.retained_bytes),
        snap.dropped_total(),
        delta.retained,
    )
}

/// Header printed once before the status lines.
#[must_use]
pub fn header(version: &str, mode: &str) -> String {
    format!("netrocket {version} — {mode}\n")
}

/// Final summary.
#[must_use]
pub fn summary(snap: &Snapshot, wall_ms: u64) -> String {
    let secs = (wall_ms as f64 / 1000.0).max(0.001);
    format!(
        "\nsummary\n\
         \x20 packets          {}\n\
         \x20 bytes            {}\n\
         \x20 average rate     {} (over the simulated interval)\n\
         \x20 flows seen       {}\n\
         \x20 shaped           {}\n\
         \x20 dropped          {} (blocked {}, policy {}, too-late {}, budget {}, quota {})\n\
         \x20 retention peak   {}\n\
         \x20 longest wait     {:.2} ms\n",
        snap.packets,
        human_bytes(snap.bytes),
        human_bps((snap.bytes as f64 / secs) as u64),
        snap.flows,
        snap.emitted_from_retention,
        snap.dropped_total(),
        snap.dropped_blocked,
        snap.dropped_policy,
        snap.dropped_late,
        snap.dropped_budget,
        snap.dropped_quota,
        human_bytes(snap.retained_peak),
        snap.max_wait_ns as f64 / 1e6,
    )
}

/// A small bar for a rate, given the maximum in the window.
///
/// Kept because `simulate --verbose` uses it to make the per-flow table
/// readable, and because it is the cheapest way to eyeball whether shaping is
/// doing anything.
#[must_use]
pub fn bar(rate_bps: u64, max_bps: u64, width: usize) -> String {
    if max_bps == 0 || width == 0 {
        return " ".repeat(width);
    }
    let filled = ((rate_bps as f64 / max_bps as f64) * width as f64).round() as usize;
    let filled = filled.min(width);
    format!("{}{}", "#".repeat(filled), ".".repeat(width - filled))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_line_has_the_numbers() {
        let snap = Snapshot {
            flows: 12,
            retained_bytes: 4096,
            ..Snapshot::default()
        };
        let delta = Delta {
            ms: 1000,
            packets: 1000,
            bytes: 125_000,
            dropped: 0,
            retained: 7,
        };
        let s = line(&snap, &delta, 5000);
        assert!(s.contains("1000 pps"), "{s}");
        assert!(s.contains("flows 12"), "{s}");
        assert!(s.contains("1.00 Mbit/s"), "{s}");
    }

    #[test]
    fn summary_is_readable() {
        let snap = Snapshot {
            packets: 100,
            bytes: 150_000,
            ..Snapshot::default()
        };
        let s = summary(&snap, 1000);
        assert!(s.contains("packets          100"));
        assert!(s.contains("150.0 KB"));
    }

    #[test]
    fn bars_are_bounded() {
        assert_eq!(bar(50, 100, 10), "#####.....");
        assert_eq!(bar(1000, 100, 4), "####");
        assert_eq!(bar(0, 0, 3), "   ");
    }
}
