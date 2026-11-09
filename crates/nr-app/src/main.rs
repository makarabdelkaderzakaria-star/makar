//! `netrocket` — command entry point.
//!
//! Exit codes are documented in `cli::help_text()` and are stable:
//! `0` success, `1` usage, `2` configuration, `3` runtime.

mod caps;
mod cli;
mod configio;
mod doctor;
mod runner;
mod tui;

use cli::Command;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = match cli::parse(args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("netrocket: {e}");
            eprintln!("try `netrocket help`");
            return ExitCode::from(1);
        }
    };

    match cmd {
        Command::Help => {
            print!("{}", cli::help_text());
            ExitCode::SUCCESS
        }
        Command::Doctor { config } => {
            let report = doctor::diagnose(&config);
            print!("{}", report.render());
            if report.failed() {
                ExitCode::from(3)
            } else {
                ExitCode::SUCCESS
            }
        }
        Command::Version => {
            println!("netrocket {}", nr_core::VERSION);
            println!(
                "target   {}-{}",
                std::env::consts::ARCH,
                std::env::consts::OS
            );
            println!("backend  {}", backend_name());
            println!("driver   {}", driver_note());
            ExitCode::SUCCESS
        }
        Command::InitConfig { path, force } => {
            if path.exists() && !force {
                eprintln!(
                    "netrocket: {} already exists (use --force to overwrite)",
                    path.display()
                );
                return ExitCode::from(2);
            }
            match configio::save_atomic(&path, &configio::template()) {
                Ok(()) => {
                    println!("wrote {}", path.display());
                    println!("next: netrocket check --config={}", path.display());
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("netrocket: {e}");
                    ExitCode::from(2)
                }
            }
        }
        Command::Check { path } => match configio::load(&path) {
            Ok(loaded) => {
                println!(
                    "ok: {} limits, {} rules, queue {} packets / {} ms",
                    loaded.config.limits.len(),
                    loaded.rule_text.len(),
                    loaded.config.queue_length,
                    loaded.config.queue_time_ms
                );
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("netrocket: {e}");
                ExitCode::from(2)
            }
        },
        Command::Lint { path } => match configio::load(&path) {
            Ok(loaded) => {
                print!("{}", configio::lint(&loaded));
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("netrocket: {e}");
                ExitCode::from(2)
            }
        },
        Command::Simulate(args) => {
            let loaded = match load_for(&args.config) {
                Ok(l) => l,
                Err(code) => return code,
            };
            if args.config.as_os_str().is_empty() {
                println!("(no --config given: simulating with defaults, nothing is shaped)\n");
            }
            match runner::simulate(&loaded, &args) {
                Ok(out) => {
                    println!("{}", tui::header(nr_core::VERSION, "simulation"));
                    let snap = out.snapshot;
                    let delta = nr_core::stats::Delta {
                        ms: (out.virtual_ns / 1_000_000).max(1),
                        packets: snap.packets,
                        bytes: snap.bytes,
                        dropped: snap.dropped_total(),
                        retained: snap.emitted_from_retention,
                    };
                    println!("{}", tui::line(&snap, &delta, out.wall_ms));
                    println!(
                        "offered {} of simulated traffic in {:.2} s of virtual time ({:.0} ms wall)",
                        nr_core::stats::human_bytes(snap.bytes),
                        out.virtual_ns as f64 / 1e9,
                        out.wall_ms
                    );
                    if args.verbose {
                        // Two bars on the same scale (frames seen): what went
                        // through immediately, and what had to be held back by
                        // a limit before it could be sent.
                        let total = snap.packets.max(1);
                        println!("\nforwarded  {}", tui::bar(out.forwarded, total, 40));
                        println!(
                            "  shaped   {}  {} frames were delayed",
                            tui::bar(snap.emitted_from_retention, total, 40),
                            snap.emitted_from_retention
                        );
                        println!(
                            "  dropped  {}  {} frames were refused",
                            tui::bar(snap.dropped_total(), total, 40),
                            snap.dropped_total()
                        );
                        println!(
                            "\nattribution: seeded {} endpoints, {} listener hints, {} packet(s) without a hint",
                            out.seeded_connected, out.seeded_listeners, out.attribution_misses
                        );
                        println!("\nflows (peak {})", out.flows);
                        println!(
                            "  forwarded {} frames / {}",
                            out.forwarded,
                            nr_core::stats::human_bytes(out.forwarded_bytes)
                        );
                        for (reason, n) in &out.drops {
                            if *n > 0 {
                                println!("  dropped {n} ({reason})");
                            }
                        }
                    }
                    if !out.limited {
                        println!(
                            "\nnote: the offered load never exceeded the configured limits,\n\
                             so nothing needed shaping. Lower a limit or raise --frames."
                        );
                    }
                    // The simulation runs on a virtual clock (bytes / offered
                    // load), so report against that, not against wall time.
                    print!(
                        "{}",
                        tui::summary(&snap, (out.virtual_ns / 1_000_000).max(1))
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("netrocket: {e}");
                    ExitCode::from(3)
                }
            }
        }
        Command::Bench(args) => {
            let loaded = match configio::load_or_default(std::path::Path::new("netrocket.conf")) {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("netrocket: {e}");
                    return ExitCode::from(2);
                }
            };
            let runs = runner::bench(loaded.config, &args);
            println!("netrocket {} — pipeline benchmark", nr_core::VERSION);
            println!("(no network I/O: this measures parse + attribute + decide)");
            println!(
                "mode: {}\n",
                if args.hot {
                    "hot frame set (pipeline cost in isolation)"
                } else {
                    "cold stream (memory-bound lower bound)"
                }
            );
            for (i, r) in runs.iter().enumerate() {
                println!(
                    "run {}: {:>8} frames  {:>7} pps  {:>10}/s  {:>6.1} ns/packet  flows {}",
                    i + 1,
                    r.frames,
                    r.pps(),
                    nr_core::stats::human_bytes(r.bytes_per_sec()),
                    r.ns_per_packet(),
                    r.flows
                );
            }
            let mut pps: Vec<u64> = runs.iter().map(|r| r.pps()).collect();
            pps.sort_unstable();
            let best = pps.last().copied().unwrap_or(0);
            let median = pps.get(pps.len() / 2).copied().unwrap_or(0);
            if let Some(first) = runs.first() {
                println!(
                    "\nworking set: {} ({} flows x {} frames)",
                    nr_core::stats::human_bytes(first.working_set),
                    args.flows,
                    if args.hot {
                        16
                    } else {
                        args.frames / args.flows.max(1)
                    }
                );
            }
            println!("best:   {best} packets/second");
            println!("median: {median} packets/second");
            ExitCode::SUCCESS
        }
        Command::Run(args) => {
            let loaded = match load_for(&args.config) {
                Ok(l) => l,
                Err(code) => return code,
            };
            match runner::run(loaded, &args) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("{e}");
                    ExitCode::from(3)
                }
            }
        }
    }
}

fn load_for(path: &std::path::Path) -> Result<configio::Loaded, ExitCode> {
    match configio::load_or_default(path) {
        Ok(l) => Ok(l),
        Err(e) => {
            eprintln!("netrocket: {e}");
            Err(ExitCode::from(2))
        }
    }
}

const fn backend_name() -> &'static str {
    if cfg!(windows) {
        "windivert (synchronous RecvEx path)"
    } else {
        "simulator only (no divert backend on this OS)"
    }
}

const fn driver_note() -> &'static str {
    if cfg!(windows) {
        "WinDivert 2.2 (LGPLv3/GPLv2), must be installed next to the executable"
    } else {
        "n/a"
    }
}
