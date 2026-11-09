# Benchmarks

**Read the scope first.** All numbers below are from the *pipeline* — parse,
attribute, decide — measured on **Linux**. The WinDivert backend cannot run
here, so no Windows throughput figure is claimed. Anything that looks like a
claim about real network throughput is a mistake in this document, not a
measurement.

## Machine

| | |
|---|---|
| CPU | Intel Xeon @ 2.60 GHz, **2 vCPU** (a shared cloud sandbox — expect noise) |
| RAM | 2 GB |
| OS | Linux x86-64 |
| Toolchain | rustc / cargo 1.99.1 |
| Profile | `release`: `opt-level=3`, `lto="fat"`, `codegen-units=1`, `panic="abort"`, `strip` |

## Pipeline throughput

```bash
cargo build --release
./target/release/netrocket bench --frames=500000 --repeat=5
```

`bench` prints its **working set** for a reason. The first version of this
benchmark sized the cycled frame set from `--frames`; at 500 k frames that was a
45 MB set, so the measurement was of the VM's memory bandwidth, and the *same
binary* reported 18 Mpps one day and 6 Mpps the next on a noisier host. The set
is now a constant 8 flows × 16 frames ≈ **98 KB**, which fits in L2 and makes the
number comparable between runs and machines.

Hot frame set, three independent invocations (5 repetitions each):

| invocation | best | median |
|---|---|---|
| 1 | 14.0 Mpps (71 ns) | 13.6 Mpps |
| 2 | 19.5 Mpps (51 ns) | 14.6 Mpps |
| 3 | 14.2 Mpps (70 ns) | 14.2 Mpps |

Reporting the **median** alongside the best is deliberate: on a shared 2 vCPU
sandbox the best-of-N flatters the code and the median is what a run actually
feels like.

Cold stream (every generated frame visited once, ~1 GB of frame bytes):

```bash
./target/release/netrocket bench --frames=200000 --repeat=3 --stream
```

| run | packets/s | bytes/s | ns/packet |
|---|---|---|---|
| 1 | 5 487 667 | 4.1 GB/s | 182.2 |
| 2 | 5 631 993 | 4.2 GB/s | 177.6 |
| 3 | 5 149 429 | 3.9 GB/s | 194.2 |

**Honest reading.** The pipeline itself costs **~50–75 ns/packet** (13–19 Mpps)
on this hardware. The `--stream` figure is a memory-bandwidth measurement of the
sandbox, not a property of the engine, and it is printed so nobody quotes the
hot number as end-to-end throughput. Earlier editions of this file reported
18.5 Mpps and 126 ns for these two cases; both were measured with the
oversized working set described above and have been replaced rather than quietly
kept because they looked better.

For scale: a 1 Gbit/s link at 1 500-byte frames is ~83 000 packets/s. The engine
needs well under 1 % of one modern core at that rate — the kernel transitions,
not the pipeline, are what will cost you.

## Zero allocation, proved rather than claimed

```bash
cargo test -p nr-core --test no_alloc
```

Three tests with a counting `#[global_allocator]` (per-thread counters, so
parallel tests cannot pollute each other):

| Test | What it asserts |
|---|---|
| `pass_through_path_never_allocates` | 100 000 packets, no rule → **0 allocations** |
| `shaping_path_allocates_only_while_the_arena_grows` | steady-state shaping → **0 allocations**; the arena reaches 200 % of its peak live bytes once and never grows again |
| `building_and_compiling_rules_allocates_only_at_startup` | 50 rules, one flow: rule table walked **exactly once** and 10 000 further packets allocate **0** |

## What this does *not* measure

* **Kernel transitions.** Every packet still crosses the driver boundary twice
  (recv, send) over a synchronous `WinDivertRecv`/`WinDivertSend`. That cost is
  not in the numbers above and is likely to dominate on real hardware.
* **Batched I/O.** `WINDIVERT_BATCH_MAX` = 255 would amortise those transitions
  ~255×, but it requires the overlapped/completion-port path, which is not
  enabled by default because it is untested here (see
  `REVERSE-ENGINEERING.md §5`). The code path is documented, not shipped as a
  default.
* **The .NET original's speed.** Building it needs the .NET 8 SDK, which is not
  installed in this environment. There is therefore **no head-to-head timing
  comparison**, and none is implied. The comparison made throughout is
  *structural*: per-packet allocations, per-packet OS calls, per-packet locks
  and a 1 ms × all-queues timer that this design does not have. Those are
  visible in the source (with line numbers in `REVERSE-ENGINEERING.md`), and
  they are the things that make a shaper feel heavy, but "N× faster than
  OpenNetLimit" is not a claim this project makes.

## Reproducing honestly

The sandbox is shared and 2 vCPU; run-to-run spread on the first repetition is
visible above (65.6 ns then 54.7 ns). Report the best of N, say N, and keep the
cold/hot distinction. A real measurement on target hardware needs:

1. a Windows box with the WinDivert driver installed,
2. a saturated link (or `iperf3 -u` to localhost) with and without shaping,
3. the driver's own counters (`WinDivert` queue drops) alongside ours.
