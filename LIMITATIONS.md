# Limitations — read before believing anything else

This file exists because a project that claims to be "faster and lighter" owes
the reader a list of what it has *not* proven.

> **This file changed again at 0.2.0.** The start-up endpoint snapshot is
> implemented and its decoder is unit-tested on Linux, the `run --monitor`
> defect is fixed, and `netrocket doctor` exists. The claim is still **not** "it
> runs on Windows" — it is "it compiles for Windows, the ABI decisions and the
> snapshot decoding are tested on every platform, and the bring-up checklist is
> written". `docs/WINDOWS-BRINGUP.md` is the list of what only hardware can
> settle.

## The Windows backend has never executed

`crates/nr-divert/src/win.rs` and the `#[cfg(windows)]` half of
`crates/nr-app/src/runner.rs` are compiled and linted for
`x86_64-pc-windows-msvc` (`cargo clippy --target ... -D warnings`, enforced in
CI on a Linux runner), but **no byte of them has run on Windows**.

What that does and does not buy you:

| Claim | Status |
|---|---|
| It compiles for Windows, with clippy clean | **proven**, in CI |
| `WINDIVERT_ADDRESS` is 80 bytes with the union at offset 16 | **asserted at compile time** on both targets |
| The bitfield map (`Outbound` = 17, `IPv6` = 20, checksums 21–23) | **unit-tested** (`win::tests::bitfield_decoding_matches_the_header`) |
| `WINDIVERT_DATA_FLOW` offsets (PID at 16, ports at 52/54, protocol 56) | **unit-tested** (`flow_layer_fields_are_read_at_the_right_offsets`) |
| A deferred packet can be re-injected without remembering a stale address | **unit-tested** via a 16-bit injection context (`pack::InjectContext`) |
| The driver accepts our re-injected packets | **untested** — needs hardware |
| `WinDivertHelperParsePacket` agreement with our own parser | **untested** — needs hardware |
| `dist/netrocket-0.2.0-windows-x64.zip` contains a working shaper | **not claimed** — the binary has never been started |

There is a compiled artifact, and its existence proves less than it looks like it
does. `netrocket.exe` in that zip is a real PE32+ x86-64 executable that links
against `IPHLPAPI`, `KERNEL32`, `ntdll`, `msvcrt` and `bcryptprimitives` — and
nothing else, because `WinDivert.dll` is resolved with `LoadLibraryW` at run
time. So the dynamic loader will not stop it from starting. What it does after
`main` begins is exactly as unproven as everything else in the table above. If
`netrocket.exe version` runs fine and `netrocket.exe run --monitor` freezes your
network, the binary is working as built and the bring-up path is wrong — that is
a bug report worth having, and `docs/WINDOWS-BRINGUP.md` step 1 exists to
provoke it in a controlled way.

The bring-up checklist is `docs/WINDOWS-BRINGUP.md`; `docs/ROADMAP.md` §0.2
lists what each step settles.

## Two design decisions made *because* of this constraint

1. **Separate receive and send handles** (`RECV_ONLY` + `SEND_ONLY`). A packet
   that is held for 200 ms cannot hand back a `WINDIVERT_ADDRESS` borrowed from
   a receive buffer that has since been reused. The retained packet therefore
   stores 16 bits of context instead of 80 bytes of address. This costs one
   extra handle and removes a whole class of bug.
2. **`sniff` is a required argument** to `Interceptor::open`. A monitor session
   that forgets `WINDIVERT_FLAG_SNIFF` diverts every matching packet and holds
   it until re-injection — i.e. it cuts the network. The first version of the
   run loop would have done exactly that. It is now a parameter nobody can
   forget, plus a test that asserts the flag is present in the monitor case and
   absent in the shaping case.

## No head-to-head comparison with the original

The .NET 8 SDK is not installed in the analysis environment, so OpenNetLimit was
never built or timed. Every comparison in these docs is structural and cites
file:line; there is no "N× faster" claim, and any number of that shape in a
third-party summary of this project is wrong.

## The benchmark machine is a 2-vCPU cloud sandbox

See `docs/BENCHMARKS.md`. The hot-frame figure (~55 ns/packet) is real and
reproducible there; the cold-stream figure is a memory-bandwidth measurement of
the sandbox, not a property of the engine. Kernel transitions, which dominate on
real hardware, are not in either number.

## Attribution's blind spot is smaller, not gone

A FLOW handle only reports flows created **after** it is opened. 0.2 closes most
of that gap by seeding attribution from the OS endpoint table
(`GetExtendedTcpTable`/`GetExtendedUdpTable`) before the network handles open:

* established connections become real 5-tuple entries, so a browser open for
  hours is attributed immediately;
* listeners become **PID hints**, because a listening socket has no peer and
  inventing a tuple for it would blame the wrong flow;
* UDP rows have no remote address at all, so they are PID hints too.

What remains unattributed:

* flows created in the gap between the snapshot and the network handles opening
  (microseconds, but not zero);
* flows the OS will not report to a non-elevated or restricted caller;
* connections that were already closed and reopened within that gap.

Anything that falls through keeps `proc_id = u32::MAX`, so **no name-based rule
can match**, and it is forwarded untouched and counted. The run loop now also
prints the first eight unattributed tuples with their packet and byte counts,
because a number alone cannot be acted on. This is still fail-closed, still
visible, and still not complete.

## The snapshot decoder is tested; the FFI call is not

`nr_divert::win_snapshot::parse` — offsets, row sizes, the big-endian port field,
listeners, v4/v6, truncated buffers — is unit-tested on Linux against
byte-identical buffers, and one test goes further: it builds a **real packet**
and checks that the snapshot's canonical key resolves it. What is *not* tested
is `GetExtendedTcpTable` itself: two-phase size query, `ERROR_INSUFFICIENT_BUFFER`
handling, and whether the rows really are laid out as `MIB_TCPROW_OWNER_PID`
documents. `netrocket doctor` reports the call's result on a real machine, and
`docs/WINDOWS-BRINGUP.md` step 1 compares the seeded tuples with
`netstat -ano`.

## Batching is not enabled

`WINDIVERT_BATCH_MAX` = 255 would amortise kernel transitions, but it needs the
overlapped/completion-port path. The reasoning for not defaulting to it is in
`docs/RESEARCH.md` §1; the short version is that shipping an untested
asynchronous receive loop as the default is how a "faster" program ends up
dropping packets.

## Simulation sheds a lot, and that is correct but misleading

`netrocket simulate` drives traffic far faster than the configured limits, from
a 64 Mbit/s offered load. The default template therefore shows six-figure drops
in a few seconds: `policy` drops are the deliberate `drop` policy of
`backup.exe`, `too-late` means the required delay exceeded the 250 ms ceiling,
and `quota` means a single flow filled its share of the retention budget.
That is the shedding design working under an unrealistic load, not a leak. A
real link offers what it offers; the simulator is a stress test.

## One lock remains

The FLOW watcher thread and the packet thread share attribution through a
`Mutex`. It is taken once per **flow event** and once per packet for the table
lookup — not per rule match, and never held across I/O. On a shaping daemon this
is irrelevant, but it is a lock, and `docs/ARCHITECTURE.md` says so instead of
claiming a lock-free design throughout.

## Single reader, single engine

The engine is `&mut self` and owned by one thread, which is why the hot path has
no locks at all. Throughput per process is bounded by one core's pipeline cost
(~13–18 Mpps here, far above any home link). Scaling to multiple reader threads
would need a sharded flow table; the `AtomicGcra` lane already exists, the
sharding does not.

## Not audited

No security review, no fuzzing campaign (the parser has unit tests for
truncation and bad lengths, which is not the same thing). `nr-core` is
`#![forbid(unsafe_code)]`, which bounds the damage a parsing bug can do, but
"no unsafe" is not "no bugs".
