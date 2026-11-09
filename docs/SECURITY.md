# Security

NetRocket sits between the network stack and every application on the machine
that talks to the network. That position is inherently privileged, so this
document states the threat model and the controls instead of assuming trust.

## Threat model

| Actor | Capability | What they could do |
|---|---|---|
| Local unprivileged user | can run `netrocket simulate/bench/check/lint`; cannot open a divert handle | should learn nothing secret and change nothing |
| Local administrator | can run `netrocket run` | can already do anything; controls are about *not widening* that |
| Another WinDivert consumer (AV, VPN) | shares the driver | can see packets at its own priority level |
| Malicious config file | supplied by anyone | must not be able to execute code or escape the config grammar |
| Network peer | sends packets | malformed frames must not crash, hang or over-read |

## Privileges

* `netrocket run` needs **Administrator**, because loading and talking to the
  WinDivert driver requires it. There is no way around this and no attempt is
  made to install a service with weaker rights.
* `netrocket simulate`, `bench`, `check`, `lint`, `init`, `version` need **no
  privileges at all** and never open a driver handle. They cannot observe or
  alter real traffic. This is deliberate: the safe mode is also the default
  experience for anyone evaluating the tool.

## Input handling

* **Packets are untrusted input.** `PacketView::parse` treats every length field
  as hostile: `IHL < 5`, `TotalLength` smaller than the header, TCP data offset
  `< 5`, truncated buffers, non-zero fragment offsets and IPv6 extension headers
  are all rejected with typed errors. There is no unbounded slice indexing and
  no arithmetic that can wrap into a smaller value in a way that changes a
  decision (`saturating_*` is used where a bound is being computed).
* **A malformed frame is forwarded, not dropped** (`pipeline.rs`): refusing to
  shape it is a decision, refusing to carry it would be censorship. It is
  counted (`parse_errors`) so the condition is visible.
* **Config files are data.** The grammar has three verbs (`param`, `limit`,
  `rule`) and one expression syntax. No shell, no include, no template
  expansion, no code path that reads a filename from the file.
* **Writes are atomic and flushed** (`configio::save_atomic`): temp file,
  `sync_all()`, `rename`. A crash leaves the old file intact; a power loss
  cannot leave a half-written one.

## Memory safety

* `nr-core` is `#![forbid(unsafe_code)]`. Every parsing bug is therefore a
  logic bug, not a memory-safety bug.
* `nr-divert` uses `unsafe` **only** on Windows, only in `win.rs`, and only in
  the FFI boundary. Every `unsafe` block is annotated with the invariant it
  relies on.
* The WinDivert ABI is asserted at **compile time**:
  `assert!(size_of::<Address>() == 80)` and `offset_of!(Address, data) == 16`.
  A future compiler or platform that changes either breaks the build instead of
  corrupting packets.
* Buffers handed to the driver are sized from `WINDIVERT_MTU_MAX`, and the
  driver's returned length is used to slice, never a length we guessed.

## Denial of service / resource limits

Every queue in the system is **bounded**, and the bounds are configuration, not
hope:

| Resource | Bound | On exhaustion |
|---|---|---|
| Retention bytes | `retain-budget` (2 MiB default) | shed the stalest packet, counted |
| Retention time | `max-retain` (250 ms default) | shed, counted |
| Per-flow retention | budget / 4 | shed, counted |
| Flow table | fixed at compile time (`Engine<FLOWS>`) | stateless policy, counted |
| Identity cache | fixed slots + fixed name arena | fail closed (`unknown`) |
| Driver queue | `queue-length` / `queue-time` / `queue-size` | the driver drops; the driver's own counters are the record |

No code path grows a `Vec` on the packet path, which removes the "memory grows
until the box dies" failure mode entirely. The allocation test in
`crates/nr-core/tests/no_alloc.rs` is what keeps this true.

## What we do *not* collect

* No telemetry, no analytics, no update check, no DNS lookups, no outbound
  connection of any kind. `nr-core` has **zero** dependencies; the workspace has
  **zero** third-party crates.
* No packet payloads are stored or logged. The connection log records a
  5-tuple and a byte count only.
* No process *paths* are persisted; only base names, in memory, with a TTL.

## WinDivert licensing and distribution

WinDivert 2.2 is dual-licensed **LGPLv3 / GPLv2**. NetRocket binds to
`WinDivert.dll` dynamically (`#[link(name = "WinDivert")]`), which is the
"use a library" case, not "derive from it". If you redistribute NetRocket
**together with** the driver binaries:

* include WinDivert's licence text and a notice that the user may replace the
  driver with a compatible version (LGPL relinking requirement),
* keep the driver in its own file, unmodified,
* do not claim the driver is part of NetRocket.

Reading `include/windivert.h` to write FFI declarations is not a licence event;
shipping `WinDivert.dll` / `WinDivert64.sys` is. `NOTICE` records the
attributions.

## Reporting

Security issues: treat this as a hobby project and open an issue with a
reproducer. Nothing here is audited; the honest statement is that the code is
small, dependency-free and allocation-free by construction, which reduces the
attack surface but does not equal an audit.
