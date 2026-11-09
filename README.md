# NetRocket

Per-application bandwidth shaping for Windows, written in Rust.

A ground-up reimplementation of the ideas in
[`SysAdminDoc/OpenNetLimit`](https://github.com/SysAdminDoc/OpenNetLimit) (MIT),
built around three rules:

1. **Fast.** ~55 ns per packet through the pipeline, zero heap allocations on
   the hot path, no locks, no timers.
2. **Light.** Zero third-party crates. Idle CPU is idle: the receive loop blocks
   on the driver instead of waking 1 000 times a second.
3. **Does not waste bandwidth.** Delay instead of drop, never hold a packet long
   enough for TCP to retransmit it, and account for every single byte.

> **Status — 0.2.0.** Core engine, CLI, simulator and tests are complete
> (148 tests on Linux, 155 on Windows). The Windows backend now covers the whole path — WinDivert
> receive/send, FLOW attribution, start-up endpoint snapshot, process identity —
> **compiles and lints clean for `x86_64-pc-windows-msvc` in CI**, and its ABI
> decisions plus the table decoder are unit-tested on every platform.
> It has still **never run on Windows**, so `netrocket run` remains alpha and
> [`docs/WINDOWS-BRINGUP.md`](docs/WINDOWS-BRINGUP.md) is the checklist that
> settles it. Everything else runs anywhere. Read
> [`LIMITATIONS.md`](LIMITATIONS.md) before trusting any number or claim here.

## Download

A Windows x64 build is attached to each release:

| File | Size | |
|---|---|---|
| `netrocket-0.2.0-windows-x64.zip` | 285 KB | `netrocket.exe` + config + driver install script + docs |

It is cross-compiled (`x86_64-pc-windows-gnu`) and **has never been executed on
Windows** — `BUILD-INFO.txt` inside the zip lists exactly what that does and does
not prove, and `SHA256SUMS` is in the same folder. WinDivert is *not* included:
`scripts/install-windivert.ps1` fetches it from the official release and checks
its signature, because shipping a kernel driver inside a zip that I could not
test would be a poor trade.

## Quick start (any OS)

```bash
cargo build --release

./target/release/netrocket init          # write netrocket.conf
./target/release/netrocket check         # validate it
./target/release/netrocket lint          # show what the engine will do
./target/release/netrocket simulate -v   # replay traffic through the real engine
./target/release/netrocket bench         # pipeline throughput
./target/release/netrocket doctor        # what is missing on this machine
```

On Windows, elevated:

```powershell
netrocket run --config=netrocket.conf
```

## Commands

| Command | Needs admin | What it does |
|---|---|---|
| `run` | yes (Windows) | intercept and shape traffic |
| `run --monitor` | yes (Windows) | count traffic, divert nothing (`WINDIVERT_FLAG_SNIFF`) |
| `run --ctl=PATH` | yes (Windows) | also serve a read-only control channel for a UI (`docs/IPC.md`) |
| `doctor` | no | check the machine can run `run`; diverts nothing |
| `simulate` | no | replay deterministic synthetic traffic through the engine |
| `bench` | no | measure the pipeline; `--stream` for the memory-bound variant |
| `init` / `check` / `lint` | no | configuration lifecycle |
| `version` | no | version + backend |

## Configuration in ten lines

```text
param max-retain = 250ms

limit chrome.exe  = 8mbit  burst 64kb
limit steam.exe   = 20mbit burst 256kb
limit backup.exe  = 2mbit  burst 32kb policy drop
limit browser.exe = 8mbit  burst 64kb per-flow
limit phone.exe   = 4mbit  burst 64kb cap 20gb/month

rule limit=chrome.exe  : proc chrome.exe
rule limit=steam.exe   : proc steam.exe
rule limit=backup.exe  : proc backup.exe
rule limit=browser.exe : proc browser.exe
```

`per-flow` gives each connection its own bucket; without it a limit is one
bucket shared by every flow the process opens. `cap` is a byte budget that
resets at 00:00 UTC daily or monthly — the metered-connection case — and its
counter survives a restart. `schedule 08:00-18:00` makes a limit exist only
during that UTC window (it may wrap midnight), which is what "do not saturate
the line while I am working" actually needs. `param codel = 5ms` bounds the
delay the retention buffer itself adds, so a saturated line does not turn into
a 200 ms-deep queue that drops nothing and helps nobody. `policy ecn` marks
congestion into the packet instead of spending a retransmission on it.

Full reference: [`docs/CONFIG.md`](docs/CONFIG.md).

## The design in one paragraph

Parse the packet with zero copies → canonical 5-tuple so both directions hit the
same flow row → attribute the flow to a rule **once** and cache the answer →
test-and-commit a GCRA rate in one atomic step → send now, or hold it in a
byte-budgeted buffer that is ordered by due time, capped at 250 ms, and sheds
the stalest packet rather than the newest. No allocation, no lock, and no OS call
happens in that path. Details: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Documentation

| File | What is in it |
|---|---|
| [`docs/REVERSE-ENGINEERING.md`](docs/REVERSE-ENGINEERING.md) | the analysis of the original, with file:line evidence and evidence tags |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | how this one is built and why |
| [`docs/RESEARCH.md`](docs/RESEARCH.md) | the WinDivert/algorithm research behind each decision |
| [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md) | measured numbers, the machine, and what is *not* measured |
| [`docs/SECURITY.md`](docs/SECURITY.md) | threat model, privileges, bounds, licensing |
| [`docs/CONFIG.md`](docs/CONFIG.md) | every parameter, limit and rule |
| [`docs/IPC.md`](docs/IPC.md) | the control channel a UI talks to, and what is untested |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | what is next and what is deliberately not planned |
| [`docs/WINDOWS-BRINGUP.md`](docs/WINDOWS-BRINGUP.md) | ordered checklist for the first real Windows run |
| [`LIMITATIONS.md`](LIMITATIONS.md) | what has **not** been proven, in one place |

## Tests

```bash
cargo test                                        # 148 tests; 155 on Windows
cargo clippy --target x86_64-pc-windows-msvc -D warnings   # the Windows backend
```

Includes three tests that use a counting global allocator to *prove* the hot
path does not allocate, and one that asserts the accounting identity
`packets == forwarded + dropped + shed + still_held` so no byte can go missing
without a counter.

## Licence

MIT — see [`LICENSE`](LICENSE). The original project is MIT; attribution is in
[`NOTICE`](NOTICE). WinDivert 2.2 (dual LGPLv3/GPLv2) is linked dynamically and
is **not** bundled here; read [`docs/SECURITY.md`](docs/SECURITY.md) before
redistributing it with these binaries.

## Origin

The sources in this repository are NetRocket 0.2.0, imported from the project's
`netrocket-0.2.0-src.tar.gz` release archive. The workspace keeps its original
layout (`crates/nr-core`, `crates/nr-divert`, `crates/nr-app`), so
`cargo build`, `cargo test` and `cargo clippy` are run from the repository root.
The only change made on import is the `repository` URL in `Cargo.toml`.
