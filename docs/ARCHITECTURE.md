# Architecture

Three crates, one direction of dependency, and a hard rule: **nothing that runs
per packet is allowed to allocate, lock, or call the OS.**

```
netrocket/
├── crates/
│   ├── nr-core/     pure logic, no I/O, no unsafe, testable on any OS
│   ├── nr-divert/   the only place that knows about WinDivert / Windows
│   └── nr-app/      CLI, runner, config files, status display
└── docs/
```

```
     ┌──────────────────────────── nr-app ────────────────────────────┐
     │  cli.rs    configio.rs    runner.rs    tui.rs                  │
     └───────────────┬───────────────────────────────┬───────────────┘
                     │ Config + CompiledRules        │ Transport
     ┌───────────────▼───────────────┐   ┌───────────▼───────────────┐
     │           nr-core             │   │         nr-divert         │
     │  packet  → flow  → rules      │   │  batch  clock  slab  sim  │
     │     ↓        ↓       ↓        │   │  win (cfg(windows))       │
     │   gcra   scheduler  stats     │   └───────────────────────────┘
     └───────────────────────────────┘
```

## The packet path, in order

`Engine::process` (`crates/nr-core/src/pipeline.rs`) is the only function that
matters for throughput. Per packet:

| Step | Cost | File |
|---|---|---|
| 1. Parse IPv4/IPv6 + TCP/UDP header, zero-copy | ~15 ns, no allocation | `packet.rs` |
| 2. Canonical 5-tuple → `FlowKey` (both directions hash alike) | one mix | `flow.rs` |
| 3. Flow row lookup | one hash, linear probe | `flow.rs` |
| 4. Rule attribution | **cached per flow** → 0 work in steady state | `rules.rs` |
| 5. GCRA test-and-commit | one subtract, one compare, one store | `gcra.rs` |
| 6. Send / retain / shed decision | branch | `scheduler.rs` |

Measured: **50–75 ns/packet** (13–19 Mpps) with a 98 KB hot frame set, and the
`pass_through_path_never_allocates` test proves **0 allocations** across
100 000 packets. See `BENCHMARKS.md` for the machine, the method, and the two
earlier figures this replaced.

## Why the flow key is canonical

Both directions of a connection produce the same `FlowKey`, because the
endpoints are sorted (`Endpoint` is `Ord`). There is no "reverse lookup" step —
which is exactly the second dictionary lookup the original performed for every
inbound packet (`FlowTracker.cs:57-62`).

## Rate control: GCRA, one word per limit

`tat` (theoretical arrival time) is the entire state. A packet conforms when

```
now >= tat - burst × cost_per_byte
```

and emitting sets `tat = max(tat, now) + len × cost_per_byte`.

Consequences that matter:

* **Atomic test-and-commit.** The original exposed `GetDelay()` and
  `TryConsume()` separately and then ignored the boolean; here the only way to
  ask is `try_acquire`, which cannot forget to commit.
* **Published as one `AtomicU64`** (`AtomicGcra`), so a second thread (statistics,
  a future multi-queue reader) can read the horizon without a lock.
* **Rate changes keep the bucket** (`Engine::set_rate`): changing a limit does
  not hand the flow a free burst, which `ProcessRateLimiter.SetLimit` did by
  rebuilding the bucket.

### Where the word lives

By default one `Gcra` per **limit**, and every flow the process opens shares it
— `process` scope. `limit <name> = <rate> per-flow` instead keeps the `tat` in
`FlowEntry::state`, the `u64` the flow row already has, and borrows the
configured lane for the single packet being decided:

```
lane = configured[limit];          // rate, burst, cost_per_byte
lane.set_tat(entry.state);         // this connection's history
lane.try_acquire(len, now);        // test and commit
entry.state = lane.tat();          // write it back
```

So a second table keyed by the same 5-tuple is never allocated, and the
`process` path — the default — never touches the extra word. The cost of
`per-flow` is two loads and two stores on the flows that opted in. When the flow
table is full, the packet falls back to the shared lane: shaping continues, just
pooled with the process. Charging still happens at **emission**, which is why
`Engine::on_emitted` takes the flow key as well as the limit index.

## Caps: bytes per period, checked before the rate

A data cap is a second budget on the same limit, and it lives in `CapState`
(one `Copy` row per configured limit, aligned with the lane vector so a rule's
limit index is all the lookup needs). It is charged on **admission**, before the
GCRA, for one reason: a packet that the retention buffer later sheds was still
demanded, and a metered link bills for what the user asked for, not for what we
managed to send in time. The order also matters for the diagnosis: a spent
budget is not a speed problem, so it must not be reported as one.

The period is a UTC day or month, decoded from the Unix clock by
`calendar.rs` (Hinnant's `civil_from_days`) instead of a date dependency — the
same reason the config parser hand-rolls its own sizes. `Engine::set_calendar`
is called once a second by the driver loop, so a laptop that resumes from
suspend, or a clock corrected by NTP, rolls the budget over instead of keeping
it spent forever. The counters are persisted by `nr-app` in `<config>.caps`,
stamped with the period they belong to; a stamp from another period is ignored
on load, so yesterday's spend can never be charged to today.

## Schedules: a limit that is not there

A `schedule` window is checked first, in `outside_window`, before anything else
costs work: outside it the limit is *absent*, not zero-rate. Packets are
forwarded with no shaping, no retention and no cap charge — a cap on a
scheduled limit is a budget for the hours the limit runs. The check is one
`Option` read plus two comparisons on the minute of the day, which the calendar
already carries (guarded by the same `Calendar` that rolls caps over, so the
daemon and the simulator cannot disagree about what time it is).

## Retention: bounded, short, and honest

`Scheduler` (`scheduler.rs`) holds packets that a shaper cannot send yet.

* **Byte budget**, not a packet count: `retain-budget = 2mb` by default.
* **Ceiling on waiting time**: `max-retain = 250ms`. Below the smallest
  plausible TCP RTO, so nothing we hold is ever retransmitted on our account.
* **Per-flow quota** of a quarter of the budget, so one bulk transfer cannot
  starve interactive traffic.
* **Ordered by due time**, so the drain step is O(packets due), not O(all held).
* **Sheds the stalest entry**, not the newest: the packet whose wait has already
  been invested is the one least worth keeping.
* **Every shed is counted** (`Snapshot::retained_shed`) and the accounting
  identity `packets == forwarded + dropped + shed + still_held` is asserted in
  tests, not just documented.

### CoDel on the way out

The drain step consults `Codel` per packet, using the sojourn time the packet
has *already* waited (see `codel.rs`). It is checked at emission rather than
admission because the question is not "is this packet slow" but "is the queue
still standing" — and only the queue's own history can answer that. A packet
CoDel refuses is removed from the buffer and counted, never silently lost.

No timer thread with a fixed heartbeat: `next_due_ns()` returns the exact
instant to wake, so an idle daemon is genuinely idle. The original armed a 1 ms
timer that scanned every queue a thousand times a second.

## Identity: resolved once per process, never per packet

```
FLOW/SOCKET event ──► ProcKey { pid, start_time } ──► IdentityCache ──► interned name id
                                                         │
                                              negative cache (protected processes)
                                              TTL, swept from the supervisor tick
```

* Keyed by `(pid, start_time)` so a recycled PID is a **different** identity.
* Negative results are cached: re-querying a protected process on every packet
  is the waste we are removing.
* Unknown ⇒ `proc_id = u32::MAX` ⇒ **no name-based rule can match**. Fail
  closed, visibly, instead of falling through to `allow`.

## Batch framing (the subtle WinDivert detail)

A batched `RecvEx` writes N addresses plus N packets back-to-back.
`WINDIVERT_ADDRESS` has **no length field**, so boundaries must come from the IP
header: `nr_divert::batch::iter_frames` reads IPv4 `TotalLength` or IPv6
`40 + PayloadLength` (`nr_core::frame::frame_len`). Calling
`WinDivertHelperParsePacket(ppNext)` per packet also works and is documented as
the fallback, but it is a function call per packet for data already in cache.

Buffers are `WINDIVERT_MTU_MAX` (65 575 bytes) × batch size, allocated **once**
and reused. The original allocated two buffers and a `ToArray()` copy per packet.

## Attribution, and the two-handle design

The `NETWORK` layer carries no PID, so attribution comes from a second handle on
the **FLOW** layer, whose events do carry `ProcessId`:

```
FLOW event ──► FlowAttribution (nr-core, unit-tested on Linux)
                 ├── by canonical 5-tuple   ← the packet path uses this
                 ├── by endpoint id         ← survives a port change
                 └── by PID                 ← when a packet arrives before its event
```

Two consequences worth naming:

* **The blind spot is seeded shut at start-up.** Before the network handles
  open, the runner asks the OS for the current endpoint table
  (`GetExtendedTcpTable`/`GetExtendedUdpTable`), so a browser that has been open
  for hours is attributed immediately instead of after its next connection.
  Established tuples become real entries; listeners and UDP rows become PID-only
  hints, because they have no peer address to invent a tuple from. Anything left
  over keeps `proc_id = u32::MAX`, no name-based rule can match it, and the run
  loop prints the first eight such tuples with their volume. Fail-closed,
  visible, and now rare.
* **Two network handles, not one.** The receive handle is opened
  `RECV_ONLY` and a separate `SEND_ONLY` handle injects. A packet held for
  200 ms therefore carries a 16-bit *injection context* (direction + priority)
  rather than an 80-byte `WINDIVERT_ADDRESS` scavenged from a receive buffer
  that has long since been reused — 8 bytes per retained packet instead of 80,
  and no way to send the wrong address.

`WINDIVERT_FLAG_SNIFF` is a required argument to `Interceptor::open`, never a
default: a monitor session without it **diverts** traffic (withholding it until
re-injection) instead of copying it. The first version of the run loop had that
bug; two tests now pin the flag on for monitor and off for shaping.

## Threading model

```
Windows:  [FLOW watcher thread] ──► Mutex<FlowAttribution> ──┐
          [recv loop thread] ────────────────────────────────┴─► Engine
                                                                  │ (single owner,
                                                                  │  no locks on the
                                                                  │  packet path)
                                                                  └─► snapshot (Copy)
                                                                       ─► status line
```

The only lock in the program sits between the watcher thread and the packet
thread, and is taken once per flow *event* plus once per packet for a table
lookup — never held across I/O, never inside rule matching.

The engine is single-threaded by construction: no mutex anywhere on the packet
path, and statistics are plain counters that are only made visible through a
`Copy` snapshot. This is the structural reason there is no lock contention to
tune later.

## Configuration

Plain text, parsed by a hand-written parser (`config.rs`), no `serde`.

```text
param queue-time = 400ms
limit chrome.exe = 8mbit burst 64kb policy shape
rule limit=chrome.exe : proc chrome.exe
```

`netrocket lint` prints exactly what the engine compiled, including the
predicates each rule actually tests — the answer to "why is nothing being
limited?".
