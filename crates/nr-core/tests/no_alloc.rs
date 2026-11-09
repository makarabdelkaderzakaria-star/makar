//! Evidence that the hot path does not allocate.
//!
//! "Faster and lighter" is easy to claim. This test proves the part that can be
//! proved mechanically: across 100 000 packets, the engine performs **zero**
//! heap allocations on the forward path, and zero once the retention arena has
//! reached its steady size on the shaping path.
//!
//! For comparison, the .NET original allocated, per packet: two receive buffers,
//! a `packetData.ToArray()` copy, a `FlowKey`/`ConnectionInfo` in the flow
//! dictionary, a rule `Clone()`, an enumerator for its LINQ query, and formatted
//! strings for the connection log.

use nr_core::config::{Config, Limits};
use nr_core::{Direction, Engine};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

// Counters are *per thread*: `cargo test` runs tests in parallel, and a global
// counter would attribute another test's rule compilation to this one's hot
// loop. `const { Cell::new(0) }` initialisation keeps the TLS access in the
// allocator allocation-free (a lazily-initialised `thread_local!` would
// recursively allocate on first touch).
thread_local! {
    static ALLOCS: Cell<usize> = const { Cell::new(0) };
}

struct Counting;

fn bump() {
    let _ = ALLOCS.try_with(|c| c.set(c.get() + 1));
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        bump();
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        bump();
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

fn current() -> usize {
    ALLOCS.with(Cell::get)
}

fn measure<F: FnOnce()>(f: F) -> usize {
    let before = current();
    f();
    current() - before
}

#[test]
fn pass_through_path_never_allocates() {
    let mut engine = Engine::<8192>::new(Config::default());
    let frame = nr_core::frame::tcp_v4([10, 0, 0, 1], 51515, [1, 1, 1, 1], 443, &[0; 1400]);

    // Warm up: the flow table inserts once per distinct flow, and `Vec::push`
    // is what allocates there. That is a one-time cost, not a per-packet one.
    engine.process(&frame, Direction::Outbound, 42, u32::MAX, 0, 0, 0);

    let allocs = measure(|| {
        for i in 1..100_000u64 {
            let _ = engine.process(
                &frame,
                Direction::Outbound,
                42,
                u32::MAX,
                0,
                i * 1_000,
                i / 1_000,
            );
        }
    });
    assert_eq!(allocs, 0, "hot path allocated {allocs} times");
    assert_eq!(engine.snapshot().packets, 100_000);
}

#[test]
fn shaping_path_allocates_only_while_the_arena_grows() {
    let mut cfg = Config::default();
    // 1 Mbit/s with a small burst: every packet after the burst is retained.
    cfg.upsert(Limits::new("slow").bits(1_000_000).burst(4_000))
        .unwrap();
    let mut engine = Engine::<8192>::new(cfg);
    let rules = vec!["limit=slow : proc slow".to_owned()];
    let (_, compiled) = Engine::<8192>::compile_rules(&rules, &engine.config().limits).unwrap();
    engine.set_rules(compiled);
    let proc_id = engine.rules().name_id("slow").expect("interned name");

    let frame = nr_core::frame::tcp_v4([10, 0, 0, 1], 51515, [1, 1, 1, 1], 443, &[0; 1400]);
    let mut now = 0u64;
    // Warm up: fill the retention arena to its steady size.
    for _ in 0..2_000 {
        let _ = engine.process(
            &frame,
            Direction::Outbound,
            7,
            proc_id,
            0,
            now,
            now / 1_000_000,
        );
        now += 1_000;
    }
    let held = engine.snapshot().retained_bytes;
    assert!(held > 0, "nothing was retained, the test proves nothing");

    let allocs = measure(|| {
        for _ in 0..10_000 {
            let _ = engine.process(
                &frame,
                Direction::Outbound,
                7,
                proc_id,
                0,
                now,
                now / 1_000_000,
            );
            now += 1_000;
        }
    });
    assert_eq!(
        allocs, 0,
        "steady-state shaping allocated {allocs} times (held {held} bytes)"
    );
}

#[test]
fn building_and_compiling_rules_allocates_only_at_startup() {
    let mut cfg = Config::default();
    for i in 0..50 {
        cfg.upsert(Limits::new(&format!("app{i}.exe")).bits(8_000_000))
            .unwrap();
    }
    // 50 `allow` rules, not `limit`: this test is about the rule cache, and a
    // limit would also exercise the retention arena (whose growth is the
    // subject of the previous test).
    let rules: Vec<String> = (0..50)
        .map(|i| format!("allow : proc app{i}.exe"))
        .collect();
    let (_, compiled) = Engine::<8192>::compile_rules(&rules, &cfg.limits).unwrap();
    let mut engine = Engine::<8192>::new(cfg);
    engine.set_rules(compiled);

    // 50 rules, one flow: the table must be walked exactly once.
    let frame = nr_core::frame::tcp_v4([10, 0, 0, 1], 51515, [1, 1, 1, 1], 443, &[0; 100]);
    let proc_id = engine.rules().name_id("app7.exe").unwrap();
    engine.process(&frame, Direction::Outbound, 1, proc_id, 0, 0, 0);
    let hits_after_first = engine.snapshot().rule_hits;
    let allocs = measure(|| {
        for i in 1..10_000u64 {
            let _ = engine.process(
                &frame,
                Direction::Outbound,
                1,
                proc_id,
                0,
                i * 1_000,
                i / 1_000,
            );
        }
    });
    assert_eq!(allocs, 0);
    assert_eq!(
        engine.snapshot().rule_hits,
        hits_after_first,
        "the rule table was re-walked for a cached flow"
    );
}
