# Research notes

What was read, what it changed in the design, and where the numbers came from.
Everything here was used to make a decision; anything that turned out to be
irrelevant was dropped rather than listed for decoration.

## 1. WinDivert 2.2 API and semantics

**Source:** the official header `include/windivert.h` (branch `master`,
mirrored locally during analysis) plus the WinDivert documentation and the
`basil00/WinDivert` wiki.

### What the header pins down

| Fact | Consequence in the code |
|---|---|
| `WINDIVERT_LAYER_NETWORK` carries **no PID**; the union holds only `IfIdx`/`SubIfIdx`. | Process attribution must come from the FLOW/SOCKET layers, never from the network layer. `win.rs::FlowEvent`. |
| `WINDIVERT_ADDRESS` has **no packet length** field. | Batch framing must derive boundaries from the IP header. `nr-divert/src/batch.rs`, `nr-core/src/frame.rs::frame_len`. |
| `WINDIVERT_MTU_MAX` = `40 + 0xFFFF`. | The receive buffer is sized for 65 575 bytes, not 1 500. `batch.rs::MTU_MAX`. |
| `QUEUE_LENGTH` default 4096, min 32, max 16384. | NetRocket defaults to **1024** and clamps. |
| `QUEUE_TIME` default 2000 ms, min 100, max 16000. | NetRocket defaults to **400 ms**: a shaper that queues 2 s is a shaper that causes retransmissions. |
| `QUEUE_SIZE` default 4 MiB, min 64 KiB, max 32 MiB. | NetRocket defaults to **1 MiB**. |
| `WINDIVERT_BATCH_MAX` = 255. | Upper bound for `Config::batch_max` (`set_param` clamps to 255). |
| `WINDIVERT_FLAG_SNIFF` copies instead of diverting. | `run --monitor` and the FLOW watcher. |
| `WinDivertHelperParsePacket(..., ppNext, pNextLen)` can walk a batch. | Not used on the hot path: it is a function call per packet, and the IP length is already in the first 4–6 bytes. Kept as the documented fallback. |
| `WinDivertShutdown` exists. | Clean stop of a blocked `recv` instead of killing the thread. `Handle::shutdown`. |

### Things the docs warn about, and where they are handled

* *"Call `WinDivertRecv` as soon as possible after `WinDivertOpen`; queued
  packets are not queued indefinitely."* → the FLOW watcher is opened before the
  network handle (`win.rs` module docs), and the receive loop never allocates.
* *"Filter as closely as possible; avoid unnecessary overhead."* → `--filter`
  exists precisely so the driver discards what we do not need. The original
  always opens with `"true"`.
* *"A packet is only diverted once per priority level; sharing a level has
  undefined ordering."* → recorded as a risk in `REVERSE-ENGINEERING.md §5`.
* There is a documented interaction between WinDivert and some debuggers that
  can deadlock; noted, not solved.

### Batching: decided against as a default

Batched `RecvEx` (255 packets per call) requires the **asynchronous** path with
an `OVERLAPPED` and an I/O completion port. Reading around the ecosystem shows
the usual failure modes: `ERROR_IO_PENDING` (997) has to be distinguished from
a real error; a pending operation's `Internal`/`Status` field is not reliably
observable without an explicit re-read; the completion port's lifetime must
outlive the handles.

Decision: implement the **synchronous** path, keep `AsyncMode` documented as
unverified, and say so in `BENCHMARKS.md`. Our measured cost per packet
(≈54–75 ns in the pipeline) means the per-packet kernel transition is the
dominant term anyway — batching would help, but shipping an untested
asynchronous loop as the default is how you get a "faster" program that drops
packets.

## 2. Rust bindings vs. hand-written FFI

**Source:** `crates.io` keyword search for `windivert`; `windivert-sys` 0.10.0
(raw bindings) and `windivert` 0.6.0 (wrapper) exist.

Decision: **hand-written FFI**, three `extern "system"` blocks.
Reasons, in order of weight:

1. `windivert-sys` generates `WINDIVERT_ADDRESS` with `bindgen`, which on
   Windows requires libclang at build time — a new build dependency for the
   user, and a frequent CI failure.
2. We need four functions and one struct. A 200-line module with compile-time
   size/offset assertions (`const _: () = { assert!(size_of::<Address>() == 80) }`)
   is smaller and auditable.
3. Licence clarity: we link dynamically to `WinDivert.dll`; no Rust crate
   licence is added to the tree.

## 3. Rate-control algorithm

Surveyed: token bucket (what the original used), leaky bucket, GCRA / virtual
scheduling, and TCP-friendly shapers (CoDel, FQ-CoDel, HTB-style hierarchies).

**Chosen: GCRA.** Why it beat the alternatives *for this program*:

| Criterion | Token bucket | GCRA |
|---|---|---|
| State | rate, tokens (`double`), last-refill timestamp | one `u64` (`tat`) |
| Check+commit atomicity | two calls, two locks | one call, one CAS |
| Drift | floating point, refill rounding | integer, exact |
| Burst handling | capacity parameter | tolerance = `burst × cost_per_byte` |
| Publishable as a single atomic word | no | yes (`AtomicGcra`) |

CoDel/FQ-CoDel were rejected as the *primary* mechanism because they control
**queue delay**, not **rate** — the user's requirement is an explicit per-app
rate. They remain a good future addition for the case "no limit configured, but
the link is congested"; that is listed in `ROADMAP.md` rather than pretended to
be done.

One honest consequence of GCRA, recorded because it looks like a bug in tests:
`bytes_emitted(T) ≤ rate·T + tolerance + one_packet`. The extra packet is
inherent — the last accepted packet's departure interval lands beyond `T`.
The tests in `gcra.rs` assert exactly this bound, not a tighter one that the
algorithm cannot provide.

## 4. Anatomy of "wasting bandwidth"

The user's requirement "must not waste the internet" was turned into four
concrete, testable rules:

1. **Never hold a packet long enough for TCP to retransmit it.** → `max_retain`
   default 250 ms, which is below the smallest plausible RTO.
2. **Prefer delay over drop.** → default policy `shape`; a delayed packet costs
   its bytes once, a dropped packet costs them twice (data + retransmission).
3. **When shedding is unavoidable, shed the least useful packet.** → the
   stalest entry (largest wait already invested) not the newest, and count it
   (`Snapshot::retained_shed`).
4. **Account for every byte.** → the accounting identity
   `packets == forwarded + dropped + shed + still_held` is asserted in a test
   (`crates/nr-app/src/runner.rs::simulation_runs_end_to_end`), not just
   documented.

## 5. Sources

* `basil00/WinDivert` — wiki documentation, `include/windivert.h`, issue
  tracker (batching, queue semantics, `ERROR_IO_PENDING`).
* `reqrypt.org/windivert-doc.html` — licensing (LGPLv3/GPLv2 dual) and driver
  installation semantics. Note: direct fetch failed in the analysis sandbox
  (DNS), so the licence statement was taken from search results **and** from
  the header in the repository; the header is authoritative for the API, the
  licence statement is corroborated but was not read on the vendor page
  directly. Flagged rather than glossed over.
* `SysAdminDoc/OpenNetLimit` — the target, pinned commit
  `f26b46cc93887fab6bbeed2091b5d365fa516e2b`.
* `morluto/rea` — methodology for evidence tagging and provenance.
* pydivert/jdivert issue threads — real-world `ERROR_IO_PENDING` and
  `OVERLAPPED` handling pitfalls that informed the "don't ship async by
  default" decision.
