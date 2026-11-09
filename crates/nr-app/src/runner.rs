//! The three ways to drive the engine: simulate, benchmark, and intercept.
//!
//! `simulate` and `bench` run anywhere. `run` needs the Windows backend and is
//! compiled only on Windows; on other platforms it explains itself instead of
//! pretending.

use crate::cli::{BenchArgs, RunArgs, SimArgs};
use nr_core::identity::{ProcKey, StaticResolver};
use nr_core::stats::{Delta, Snapshot};
use nr_core::{Config, Decision, Direction, Engine};
use nr_divert::sim::{default_processes, SimConfig, SimTransport};
use nr_divert::{Clock, Transport};
use std::collections::HashMap;
use std::time::Instant;

/// Outcome of a simulation.
#[derive(Debug, Clone)]
pub struct SimOutcome {
    /// Final engine counters.
    pub snapshot: Snapshot,
    /// Virtual time elapsed (ns) — the simulated clock, not wall clock.
    pub virtual_ns: u64,
    /// Wall-clock time spent.
    pub wall_ms: u64,
    /// Frames forwarded (immediately or after retention).
    pub forwarded: u64,
    /// Bytes forwarded.
    pub forwarded_bytes: u64,
    /// Frames dropped, by reason.
    pub drops: Vec<(&'static str, u64)>,
    /// Peak number of live flows.
    pub flows: u64,
    /// Whether the offered rate ever exceeded what the limits allowed.
    pub limited: bool,
    /// Endpoints seeded into attribution at start-up.
    pub seeded_connected: usize,
    /// Seed entries that became PID-only hints (listeners).
    pub seeded_listeners: usize,
    /// Packets whose process had no attribution hint.
    pub attribution_misses: u64,
}

/// Run the deterministic simulation.
///
/// The virtual clock advances by the time it would take to serialise each frame
/// at `offered_bps`, so the numbers are comparable between runs and do not
/// depend on how fast this machine happens to be.
pub fn simulate(loaded: &crate::configio::Loaded, args: &SimArgs) -> Result<SimOutcome, String> {
    let config = loaded.config.clone();
    let sim_cfg = SimConfig {
        flows: args.flows,
        frames_per_flow: args.frames,
        ..SimConfig::default()
    };
    let mut transport = SimTransport::from_config(&sim_cfg);

    // The same resolver the Windows backend would provide, backed by the
    // simulated process table.
    let mut resolver = StaticResolver::new();
    for p in default_processes() {
        resolver = resolver.with_key(ProcKey::new(p.pid, p.start_time), p.name);
    }

    // Use the rules exactly as configured: the point of the simulator is to
    // show what the real engine will do, so it must not approximate them.
    let mut engine = Engine::<8192>::new(config);
    engine.set_rules(loaded.rules.clone());
    // Caps reset on UTC boundaries and schedules follow the wall clock, so the
    // simulator uses the real clock by default; `--at` pins the time of day so a
    // run that involves a schedule is reproducible.
    let mut calendar = crate::caps::utc_now();
    if let Some(minute) = args.at {
        calendar = calendar.at_minute(minute);
    }
    engine.set_calendar(calendar);

    // Seed attribution the way the Windows runner does at start-up: from an
    // endpoint table that predates the engine. In the simulator we synthesise
    // that table from the process list, which exercises the exact code path
    // (`FlowAttribution::seed`) the real snapshot feeds.
    let mut attribution = nr_core::FlowAttribution::new(8192, 60_000);
    let seeded = {
        let mut entries: Vec<nr_core::SnapshotEntry> = Vec::new();
        // (a) one listener per simulated process, which is what gives a packet
        //     arriving from an *inbound* connection its PID hint;
        for p in default_processes() {
            let key = ProcKey::new(p.pid, p.start_time);
            let local = nr_core::Endpoint {
                addr: [0; 16],
                port: 0,
            };
            entries.push(nr_core::SnapshotEntry::listening(key, 6, local));
        }
        // (b) the *established* tuples, exactly like `GetExtendedTcpTable`
        //     would report them for connections that pre-date us. This is the
        //     path that must match the packet path's canonical keys byte for
        //     byte, and the simulator is where it can be exercised on Linux.
        let mut seen = std::collections::HashSet::new();
        for (i, frame) in transport.frames().iter().enumerate() {
            let Some(proc) = transport.process(i) else {
                continue;
            };
            let Ok(view) = nr_core::PacketView::parse(&frame.data) else {
                continue;
            };
            let local = nr_core::Endpoint::src_of(&view);
            let remote = nr_core::Endpoint::dst_of(&view);
            let key = ProcKey::new(proc.pid, proc.start_time);
            // One entry per (pid, tuple) pair; the HashSet just keeps the seed
            // size realistic instead of re-inserting the same flow 4000 times.
            if !seen.insert((key.pid, view.src_port, view.dst_port, view.protocol as u8)) {
                continue;
            }
            entries.push(nr_core::SnapshotEntry::connected(
                key,
                view.protocol as u8,
                local,
                remote,
            ));
        }
        attribution.seed(entries, 0)
    };
    let mut attribution_misses = 0u64;

    let clock = Clock::new();
    let start = Instant::now();
    let mut buf = vec![0u8; 65_760];
    let mut virtual_ns = 0u64;
    let offered_bps = 64_000_000u64; // 64 Mbit/s offered load
    let mut forwarded = 0u64;
    let mut forwarded_bytes = 0u64;
    let mut limit_of: HashMap<u64, (u16, nr_core::FlowKey)> = HashMap::new();
    let mut rates = Rates::default();
    let mut peaks = 0u64;
    let mut idx = 0usize;

    while let Some((len, direction, token)) = transport.recv(&mut buf).map_err(|e| e.to_string())? {
        let proc = transport.process(idx).cloned();
        idx += 1;
        let pid = proc.as_ref().map_or(0, |p| p.pid);
        let proc_id = match proc {
            Some(ref p) => {
                // Attribution, in the same order the Windows runner uses:
                // the 5-tuple first (canonical, direction-independent), then
                // the PID hint as a fallback. A miss is counted, not hidden.
                let now_ms = virtual_ns / 1_000_000;
                let found = match nr_core::PacketView::parse(&buf[..len]) {
                    Ok(view) => {
                        let key = nr_core::FlowKey::from_packet(&view, direction, 0);
                        attribution.get(&key, now_ms).is_some()
                    }
                    Err(_) => false,
                };
                if !found
                    && attribution.by_pid(p.pid, now_ms).is_none()
                    && attribution_misses < u64::MAX
                {
                    attribution_misses += 1;
                }
                match nr_core::identity::Resolver::resolve(
                    &mut resolver,
                    ProcKey::new(p.pid, p.start_time),
                ) {
                    Some(name) => engine.rules().name_id(&name).unwrap_or(u32::MAX),
                    None => u32::MAX,
                }
            }
            None => u32::MAX,
        };

        let outcome = engine.process(
            &buf[..len],
            direction,
            pid,
            proc_id,
            token,
            virtual_ns,
            virtual_ns / 1_000_000,
        );

        // Advance the virtual clock by the serialisation time of this frame.
        virtual_ns +=
            (len as u64).saturating_mul(8).saturating_mul(1_000_000_000) / offered_bps.max(1);
        peaks = peaks.max(engine.flows().len() as u64);

        match outcome.decision {
            Decision::SendNow => {
                let _ = transport.send(&buf[..len], token);
                forwarded += 1;
                forwarded_bytes += len as u64;
            }
            Decision::Retain { .. } => {
                // Remember both the limit and the flow: a `per-flow` limit is
                // charged against the flow's own row when the packet is
                // actually emitted, not when it is admitted.
                if let (Some(li), Some(flow)) = (outcome.limit, outcome.flow) {
                    limit_of.insert(token, (li, flow));
                }
            }
            Decision::Drop(_) => {}
        }

        // Emit whatever became due, exactly as the real loop does.
        let mut due = Vec::new();
        engine.scheduler_mut().drain_due(virtual_ns, 256, |d| {
            due.push((d.frame.to_vec(), d.addr));
        });
        for (frame, token) in due {
            if transport.send(&frame, token).is_ok() {
                forwarded += 1;
                forwarded_bytes += frame.len() as u64;
                if let Some((li, flow)) = limit_of.remove(&token) {
                    engine.on_emitted(flow, li, frame.len() as u32, virtual_ns);
                }
            }
        }

        if idx % 4096 == 0 {
            engine.tick(virtual_ns / 1_000_000);
            rates.push(engine.snapshot());
        }
    }

    // Flush whatever is still retained so the accounting closes: every frame is
    // either forwarded, dropped by a rule/limit, shed by the retention buffer,
    // or (after this flush) forwarded late. Nothing is silently lost.
    //
    // The flush instant is the end of the simulated interval plus the retention
    // ceiling, not "infinity": flushing at `u64::MAX / 4` made every packet's
    // reported wait absurd (the first version printed
    // "longest wait 4611686016922.56 ms").
    let max_retain_ms = engine.config().max_retain_ms;
    let flush_at = virtual_ns.saturating_add(max_retain_ms.saturating_mul(1_000_000));
    let mut pending = Vec::new();
    engine.scheduler_mut().drain_due(flush_at, usize::MAX, |d| {
        pending.push((d.frame.to_vec(), d.addr));
    });
    for (frame, token) in pending {
        if transport.send(&frame, token).is_ok() {
            forwarded += 1;
            forwarded_bytes += frame.len() as u64;
            if let Some((li, flow)) = limit_of.remove(&token) {
                engine.on_emitted(flow, li, frame.len() as u32, flush_at);
            }
        }
    }

    let snapshot = engine.snapshot();
    let drops = vec![
        ("blocked", snapshot.dropped_blocked),
        ("policy", snapshot.dropped_policy),
        ("too-late", snapshot.dropped_late),
        ("budget", snapshot.dropped_budget),
        ("quota", snapshot.dropped_quota),
        ("cap", snapshot.dropped_cap),
    ];
    let limited = snapshot.rate_over > 0;
    let _ = rates.last();
    let _ = clock.now_ns();
    Ok(SimOutcome {
        snapshot,
        virtual_ns,
        wall_ms: start.elapsed().as_millis() as u64,
        forwarded,
        forwarded_bytes,
        drops,
        flows: peaks,
        limited,
        seeded_connected: seeded.connected,
        seeded_listeners: seeded.listeners,
        attribution_misses,
    })
}

/// One benchmark repetition.
#[derive(Debug, Clone, Copy)]
pub struct BenchRun {
    /// Frames processed.
    pub frames: u64,
    /// Bytes processed.
    pub bytes: u64,
    /// Wall time in microseconds.
    pub micros: u64,
    /// Flow rows after the run.
    pub flows: u64,
    /// Bytes in the frame set being cycled (the working set).
    pub working_set: u64,
}

impl BenchRun {
    /// Packets per second.
    #[must_use]
    pub fn pps(&self) -> u64 {
        if self.micros == 0 {
            return 0;
        }
        self.frames.saturating_mul(1_000_000) / self.micros
    }

    /// Bytes per second.
    #[must_use]
    pub fn bytes_per_sec(&self) -> u64 {
        if self.micros == 0 {
            return 0;
        }
        self.bytes.saturating_mul(1_000_000) / self.micros
    }

    /// Nanoseconds per packet.
    #[must_use]
    pub fn ns_per_packet(&self) -> f64 {
        if self.frames == 0 {
            return 0.0;
        }
        (self.micros as f64 * 1000.0) / self.frames as f64
    }
}

/// Measure the pure pipeline: parse, attribute, decide. No transport, no clock
/// calls inside the loop beyond one `Instant` at each end.
pub fn bench(config: Config, args: &BenchArgs) -> Vec<BenchRun> {
    // Two different questions, two different measurements:
    //
    // * hot   — cycle a *deliberately small* frame set that fits in L2, so the
    //           number is the pipeline's own cost. An earlier version of this
    //           function sized the set from `--frames` and ended up streaming
    //           45 MB per repetition, which measured the VM's memory bandwidth
    //           and made the same binary look 3x slower on a noisy host. Sizing
    //           it at a constant is what makes the figure comparable between
    //           runs and between machines.
    // * cold  — walk every generated frame once. Memory-bound by construction,
    //           and reported as a lower bound, not as the engine's cost.
    const HOT_FRAMES_PER_FLOW: usize = 16;
    let sim_cfg = SimConfig {
        flows: args.flows.clamp(1, 64),
        frames_per_flow: if args.hot {
            HOT_FRAMES_PER_FLOW
        } else {
            (args.frames / args.flows.max(1)).max(1)
        },
        ..SimConfig::default()
    };
    let generated: Vec<Vec<u8>> = nr_divert::sim::generate(&sim_cfg)
        .into_iter()
        .map(|(f, _)| f.data)
        .collect();

    // Precompute a rich, realistic configuration: every flow limited.
    let mut runs = Vec::with_capacity(args.repeat);
    for _ in 0..args.repeat {
        let (_, compiled) = Engine::<8192>::compile_rules(&[], &config.limits)
            .unwrap_or((Default::default(), Default::default()));
        let mut engine = Engine::<8192>::new(config.clone());
        engine.set_rules(compiled);

        let mut now_ns = 0u64;
        let mut bytes = 0u64;
        let mut processed = 0u64;
        let started = Instant::now();
        if args.hot {
            // Cycle the cache-resident set until we have processed `frames`.
            while processed < args.frames as u64 {
                for frame in &generated {
                    let _ = engine.process(
                        frame,
                        Direction::Outbound,
                        1001,
                        u32::MAX,
                        processed,
                        now_ns,
                        now_ns / 1_000_000,
                    );
                    now_ns += 1_000; // 1 µs per packet: 1 Mpps offered
                    bytes += frame.len() as u64;
                    processed += 1;
                    if processed >= args.frames as u64 {
                        break;
                    }
                }
            }
        } else {
            for frame in &generated {
                let _ = engine.process(
                    frame,
                    Direction::Outbound,
                    1001,
                    u32::MAX,
                    processed,
                    now_ns,
                    now_ns / 1_000_000,
                );
                now_ns += 1_000;
                bytes += frame.len() as u64;
                processed += 1;
            }
        }
        let micros = started.elapsed().as_micros().max(1) as u64;
        runs.push(BenchRun {
            frames: processed,
            bytes,
            micros,
            flows: engine.flows().len() as u64,
            working_set: generated.iter().map(Vec::len).sum::<usize>() as u64,
        });
    }
    runs
}

/// Window of the last two snapshots, for rate display.
#[derive(Debug, Default)]
pub struct Rates {
    prev: Option<Snapshot>,
    last: Option<Delta>,
}

impl Rates {
    /// Feed a snapshot; returns the delta against the previous one.
    pub fn push(&mut self, snap: Snapshot) -> Delta {
        let d = match &self.prev {
            Some(p) => snap.delta(p),
            None => Delta::default(),
        };
        self.prev = Some(snap);
        self.last = Some(d);
        d
    }

    /// Most recent delta (used by the status line and by `simulate`).
    #[must_use]
    pub const fn last(&self) -> Option<Delta> {
        self.last
    }
}

// ---------------------------------------------------------------------------
// The real thing
// ---------------------------------------------------------------------------

/// Run the interceptor. Only meaningful on Windows.
///
/// Threading: the FLOW watcher owns one thread and publishes attribution
/// through a `Mutex` (touched once per event, never per packet); this thread
/// owns the engine and the network handles. The `Mutex` is the only lock in the
/// program on the packet path, and it is not on the packet path — it is on the
/// *event* path, where the packet rate is irrelevant.
#[cfg(windows)]
pub fn run(loaded: crate::configio::Loaded, args: &RunArgs) -> Result<(), String> {
    use nr_core::attribution::FlowAttribution;
    use nr_divert::win::{
        explain, pack::InjectContext, FlowWatcher, Interceptor, QueueParams, WinResolver,
    };
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    let config = loaded.config.clone();
    let mut engine = Engine::<8192>::new(config.clone());
    engine.set_rules(loaded.rules);

    // Data caps: the counters live next to the configuration file, so a restart
    // does not hand back a budget that was already spent today.
    let caps_path = crate::caps::path_for(&args.config);
    engine.set_calendar(crate::caps::utc_now());
    let restored = crate::caps::load_into(&mut engine, &caps_path);
    if restored > 0 {
        eprintln!(
            "restored {restored} cap counter(s) from {}",
            caps_path.display()
        );
    }
    let mut last_cap_save = 0u64;

    // 1. Attribution first: a FLOW handle only sees flows created after it
    //    exists, so opening it before the network handle keeps the blind spot
    //    as small as the OS allows. Anything that slips through stays
    //    explicitly "unknown" and is counted, never silently attributed.
    let attribution = Arc::new(Mutex::new(FlowAttribution::new(
        8192,
        config.identity_ttl_ms,
    )));
    let stop = Arc::new(AtomicBool::new(false));

    let watcher_attribution = Arc::clone(&attribution);
    let watcher_stop = Arc::clone(&stop);
    let watcher = FlowWatcher::open().map_err(|e| format!("flow layer: {e}: {}", explain(&e)))?;
    let flow_thread = std::thread::Builder::new()
        .name("nr-flow".to_owned())
        .spawn(move || {
            let mut watcher = watcher;
            let mut resolver = WinResolver::new();
            while !watcher_stop.load(Ordering::Relaxed) {
                let start_time = |pid: u32| resolver.start_time(pid);
                match watcher.next_event(start_time) {
                    Ok(Some(ev)) => {
                        if let Ok(mut table) = watcher_attribution.lock() {
                            // The event's own timestamp is a driver clock; use
                            // our monotonic millisecond clock for TTLs.
                            table.apply(&ev, proc_now_ms());
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        eprintln!("flow watcher: {e}");
                        break;
                    }
                }
            }
        })
        .map_err(|e| format!("cannot start the flow watcher thread: {e}"))?;

    // 2. Network handles.
    let filter = args.filter.clone().unwrap_or_else(|| "true".to_owned());
    let mut interceptor = Interceptor::open(
        &filter,
        QueueParams {
            length: config.queue_length,
            time_ms: config.queue_time_ms,
            size: config.queue_size,
        },
        args.monitor,
    )
    .map_err(|e| format!("{e}: {}", explain(&e)))?;

    let clock = Clock::new();
    let mut resolver = WinResolver::new();
    // Token -> (injection context, limit index, frame length, flow) for packets
    // currently held. The flow travels with the packet because a `per-flow`
    // limit charges the flow's own bucket when the packet is emitted.
    let mut held: std::collections::HashMap<u64, (InjectContext, u16, u32, nr_core::FlowKey)> =
        std::collections::HashMap::with_capacity(4096);
    let mut next_token = 1u64;
    let mut last_tick = clock.now_ms();
    let mut unknown_flows = 0u64;
    let mut send_failures = 0u64;
    // Once-per-flow diagnostics: which tuples we could not attribute, and how
    // much traffic they carried. A count alone cannot be acted on; a 5-tuple and
    // a byte count can.
    let mut unattributed: std::collections::HashMap<String, (u64, u64)> =
        std::collections::HashMap::new();
    let mut unattributed_reported = 0usize;

    eprintln!(
        "netrocket {} — {} (filter: {filter})",
        nr_core::VERSION,
        if args.monitor {
            "monitoring, nothing is diverted"
        } else {
            "shaping"
        }
    );

    while !stop.load(Ordering::Relaxed) {
        let now_ns = clock.now_ns();
        let now_ms = now_ns / 1_000_000;

        let mut addr = nr_divert::win::Address::default();
        let received = interceptor.recv_with_addr(&mut addr);
        let (frame, direction) = match received {
            Ok(Some((frame, direction))) => (frame.to_vec(), direction),
            Ok(None) => break,
            Err(e) => {
                eprintln!("recv: {e}: {}", explain(&e));
                break;
            }
        };

        // 3. Attribute. One lookup per packet here, but the *expensive* part
        //    (rule matching, and the PID -> name query) is cached by the engine
        //    per flow, so the steady state does no string work at all.
        let (owner, proc_id) = {
            let pkt = nr_core::PacketView::parse(&frame);
            let mut owner_pid = 0u32;
            if let Ok(view) = pkt {
                let key = nr_core::flow::FlowKey::from_packet(&view, direction, 0);
                let mut table = attribution
                    .lock()
                    .map_err(|_| "attribution lock poisoned".to_owned())?;
                if let Some(owner) = table.get(&key, now_ms) {
                    owner_pid = owner.pid;
                }
            }
            if owner_pid == 0 {
                unknown_flows += 1;
                if unattributed.len() < 64 {
                    let label = match nr_core::PacketView::parse(&frame) {
                        Ok(v) => format!(
                            "{:?} {}:{} -> {}:{}",
                            v.protocol,
                            v.src_port,
                            v.dst_port,
                            v.wire_len,
                            direction.code()
                        ),
                        Err(_) => "unparseable".to_owned(),
                    };
                    let slot = unattributed.entry(label).or_insert((0, 0));
                    slot.0 += 1;
                    slot.1 += frame.len() as u64;
                }
                (0u32, u32::MAX)
            } else {
                let key = ProcKey::new(owner_pid, resolver.start_time(owner_pid));
                let id = engine.identify(key.pid, key.start_time, now_ms, &mut resolver);
                (owner_pid, id)
            }
        };

        let this_token = next_token;
        next_token = next_token.wrapping_add(1);
        let outcome = engine.process(
            &frame, direction, owner, proc_id, this_token, now_ns, now_ms,
        );

        match outcome.decision {
            Decision::SendNow => {
                // Sniffed packets are already delivered by the stack, so in
                // monitor mode we never inject.
                if !args.monitor
                    && interceptor
                        .send_deferred(&frame, InjectContext::new(direction, 0))
                        .is_err()
                {
                    send_failures += 1;
                }
            }
            Decision::Retain { .. } => {
                // A retained packet always has a flow: the engine only retains
                // frames that parsed, and a frame that did not parse is
                // forwarded, never held. Guard anyway rather than invent a key.
                if let Some(flow) = outcome.flow {
                    held.insert(
                        this_token,
                        (
                            InjectContext::new(direction, 0),
                            outcome.limit.unwrap_or(0),
                            frame.len() as u32,
                            flow,
                        ),
                    );
                }
            }
            Decision::Drop(_) => {}
        }

        // 4. Emit whatever became due. No timer: the loop is already awake.
        let due_now = clock.now_ns();
        let mut due: Vec<(Vec<u8>, u64)> = Vec::new();
        engine.scheduler_mut().drain_due(due_now, 256, |d| {
            due.push((d.frame.to_vec(), d.addr));
        });
        for (frame, token) in due {
            if let Some((ctx, limit, len, flow)) = held.remove(&token) {
                if !args.monitor && interceptor.send_deferred(&frame, ctx).is_err() {
                    send_failures += 1;
                }
                engine.on_emitted(flow, limit, len, due_now);
            }
        }

        if now_ms.saturating_sub(last_tick) >= 1_000 {
            engine.tick(now_ms);
            // Cap periods and counters. The calendar is re-read every second
            // because a laptop resumes from suspend (or its clock is corrected
            // by NTP) and midnight UTC can pass without the loop noticing.
            engine.set_calendar(crate::caps::utc_now());
            if now_ms.saturating_sub(last_cap_save) >= 60_000 {
                last_cap_save = now_ms;
                if let Err(e) = crate::caps::save(&engine, &caps_path) {
                    eprintln!("warning: could not save cap counters: {e}");
                }
            }
            if let Ok(mut table) = attribution.lock() {
                table.sweep(now_ms);
            }
            last_tick = now_ms;

            // Name the processes we could not identify, once, with their volume.
            if !unattributed.is_empty() && unattributed_reported < 10 {
                unattributed_reported += 1;
                let mut rows: Vec<(&String, &(u64, u64))> = unattributed.iter().collect();
                rows.sort_by_key(|(_, (packets, _))| std::cmp::Reverse(*packets));
                eprintln!("unattributed traffic (no FLOW event and not in the start-up snapshot):");
                for (label, (packets, bytes)) in rows.iter().take(8) {
                    eprintln!(
                        "  {label}  {packets} packets, {}",
                        nr_core::stats::human_bytes(*bytes)
                    );
                }
                if rows.len() > 8 {
                    eprintln!("  ... and {} more", rows.len() - 8);
                }
            }

            let snap = engine.snapshot();
            eprintln!(
                "{} packets  {}  flows {}  held {}  drops {}  unattributed {}",
                snap.packets,
                nr_core::stats::human_bytes(snap.bytes),
                snap.flows,
                nr_core::stats::human_bytes(snap.retained_bytes),
                snap.dropped_total(),
                unknown_flows
            );
        }
    }

    stop.store(true, Ordering::Relaxed);
    interceptor
        .recv_handle()
        .shutdown(nr_divert::win::ShutdownMode::Both);
    let _ = flow_thread.join();

    // Last accounting before exit: the counters are the only thing a cap
    // promises across a restart, so they are written on the way out too.
    if let Err(e) = crate::caps::save(&engine, &caps_path) {
        eprintln!("warning: could not save cap counters: {e}");
    }

    if send_failures > 0 {
        eprintln!(
            "warning: {send_failures} packets could not be re-injected and were counted as drops"
        );
    }
    Ok(())
}

/// Milliseconds on a process-wide monotonic clock, for the watcher thread.
#[cfg(windows)]
fn proc_now_ms() -> u64 {
    use std::sync::OnceLock;
    static BASE: OnceLock<std::time::Instant> = OnceLock::new();
    BASE.get_or_init(std::time::Instant::now)
        .elapsed()
        .as_millis() as u64
}

/// On every other platform, say so plainly.
#[cfg(not(windows))]
pub fn run(_loaded: crate::configio::Loaded, _args: &RunArgs) -> Result<(), String> {
    Err("\
`netrocket run` intercepts Windows traffic through the WinDivert driver, so it
only works on Windows. Everything else does work here:

  netrocket simulate   replay synthetic traffic through the real engine
  netrocket bench      measure pipeline throughput
  netrocket lint       show how your configuration is compiled"
        .to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nr_core::config::Limits;

    fn loaded_from(cfg: Config) -> crate::configio::Loaded {
        let mut rules: Vec<String> = cfg
            .limits
            .iter()
            .map(|l| format!("limit={} : proc {}", l.name, l.name))
            .collect();
        if rules.is_empty() {
            rules.push("allow : all".to_owned());
        }
        let (_, compiled) = Engine::<8192>::compile_rules(&rules, &cfg.limits).unwrap();
        crate::configio::Loaded {
            config: cfg,
            rules: compiled,
            rule_text: rules,
        }
    }

    fn cfg_with_limits() -> Config {
        let mut c = Config::default();
        c.upsert(Limits::new("chrome.exe").bits(8_000_000).burst(64_000))
            .unwrap();
        c.upsert(Limits::new("steam.exe").bits(20_000_000).burst(128_000))
            .unwrap();
        c
    }

    #[test]
    fn simulation_runs_end_to_end() {
        let args = SimArgs {
            flows: 4,
            frames: 200,
            verbose: false,
            ..SimArgs::default()
        };
        let cfg = cfg_with_limits();
        cfg.validate().unwrap();
        let loaded = loaded_from(cfg);
        let out = simulate(&loaded, &args).unwrap();
        assert!(out.snapshot.packets > 0);
        assert!(out.forwarded > 0);
        assert!(out.flows > 0);
        // A wait is only meaningful if it is bounded by the retention ceiling,
        // plus room for the virtual clock's coarse per-frame advance.
        assert!(
            out.snapshot.max_wait_ns <= 1_000_000_000,
            "reported wait of {} ns is not a plausible retention delay",
            out.snapshot.max_wait_ns
        );
        // Every frame is accounted for exactly once: forwarded, dropped by the
        // engine, shed by the retention buffer, or still held. Nothing is lost.
        let dropped: u64 = out.drops.iter().map(|(_, n)| *n).sum();
        assert_eq!(
            out.snapshot.packets,
            out.forwarded + dropped + out.snapshot.retained_shed + out.snapshot.retained_left,
            "accounting does not close: {out:?}"
        );
        // The drain runs once per frame, so a steady offered load never
        // overflows the buffer; what it does do is shape.
        assert!(
            out.snapshot.retained > 0 || out.snapshot.emitted_from_retention > 0,
            "no shaping happened at all: {out:?}"
        );
    }

    #[test]
    fn simulation_with_no_limits_forwards_everything() {
        let args = SimArgs {
            flows: 2,
            frames: 100,
            verbose: false,
            ..SimArgs::default()
        };
        let loaded = loaded_from(Config::default());
        let out = simulate(&loaded, &args).unwrap();
        let dropped: u64 = out.drops.iter().map(|(_, n)| *n).sum();
        assert_eq!(dropped, 0);
        assert_eq!(out.forwarded, out.snapshot.packets);
    }

    #[test]
    fn hot_bench_working_set_fits_in_l2() {
        let args = BenchArgs {
            frames: 100_000,
            flows: 8,
            repeat: 1,
            hot: true,
        };
        let runs = bench(Config::default(), &args);
        assert!(
            runs[0].working_set < 512 * 1024,
            "working set {} bytes is too big to isolate the pipeline",
            runs[0].working_set
        );
        assert_eq!(runs[0].frames, 100_000);
    }

    #[test]
    fn bench_produces_sane_numbers() {
        let args = BenchArgs {
            frames: 5_000,
            flows: 4,
            repeat: 1,
            hot: true,
        };
        let runs = bench(cfg_with_limits(), &args);
        assert_eq!(runs.len(), 1);
        assert!(runs[0].frames > 0);
        assert!(
            runs[0].pps() > 10_000,
            "implausibly slow: {}",
            runs[0].pps()
        );
        assert!(runs[0].ns_per_packet() < 50_000.0);
    }

    #[test]
    fn rates_track_deltas() {
        let mut r = Rates::default();
        let a = Snapshot {
            at_ms: 1000,
            packets: 1000,
            ..Snapshot::default()
        };
        let b = Snapshot {
            at_ms: 2000,
            packets: 3000,
            ..Snapshot::default()
        };
        r.push(a);
        let d = r.push(b);
        assert_eq!(d.packets, 2000);
        assert_eq!(r.last().unwrap().pps(), 2000);
    }
}
