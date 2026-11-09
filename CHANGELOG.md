# Changelog

## Unreleased

### Added

* **CoDel queue management (`param codel = 5ms`).** A byte budget bounds how
  much is held but not how long it stands: a queue that is always 200 ms deep
  drops nothing and makes everything feel slow. `Codel` (RFC 8289) now watches
  the sojourn time of the packets we retain and, once the minimum has been above
  the target for a whole interval, drops the packets that would arrive late
  instead of delivering them late, tightening the spacing as
  `interval / sqrt(count)` while the queue persists. Off by default (one
  comparison on the drain path), 100 ms interval by default, and every drop is
  counted in `retained_codel` and included in `retained_shed`, so the accounting
  identity keeps holding. Tests: a burst below target is never punished, a
  standing queue starts dropping after one interval, drops escalate, a draining
  queue resets the episode, the scheduler sheds only when armed, and the
  integer square root the spacing depends on.
* **Time-of-day schedules.** `limit steam.exe = 4mbit schedule 08:00-18:00`
  (or `schedule 22:00-06:00`, which wraps midnight) enforces the limit only
  inside that **UTC** window; outside it the limit does not exist -- packets go
  out immediately and no cap is charged, so a cap on a scheduled limit is a
  budget for the hours it runs. Windows are start-inclusive and end-exclusive,
  bare hours (`8-18`) are accepted, and a zero-length or impossible window is
  rejected at parse time. `lint` prints the window, and `simulate --at=09:30`
  pins the clock so schedule tests are deterministic. Weekdays are not
  supported yet. Tests: inside/outside, a window wrapping midnight, a cap not
  charged outside, membership on both sides of midnight, and the parse
  rejections.
* **Data caps: a byte budget per day or month.** `limit phone.exe = 4mbit cap
  20gb/month` (or `cap 2gb/day`) drops matching traffic once the budget is
  spent, which is what a metered connection needs far more than a rate limit.
  Bytes are charged on admission in both directions, so a packet the retention
  buffer sheds still counts. Periods roll over at 00:00 **UTC** — deliberately
  not local time, which would need a timezone database. The counter is
  persisted in `<config>.caps` with the period stamp it belongs to, so a
  restart (or a counter file from yesterday) cannot refund a spent budget; a
  crash costs at most the last minute of accounting. New drop reason `cap`,
  counted in `simulate`, the daemon status line and the TUI. `nr-core::calendar`
  decodes UTC day/month from the Unix clock with no date dependency, tested
  against independently computed dates including a leap day and 2100 (not a
  leap year).
* **`per-flow` limit scope.** `limit browser.exe = 8mbit per-flow` (or
  `scope flow`) gives every connection its own GCRA lane instead of pooling the
  process's flows into one bucket, so one saturated transfer no longer starves
  the rest of the process — a browser streaming 4K stops breaking its own DNS.
  The state is the `u64` the flow row already carries, so it costs no second
  table, no allocation and no extra hashing on the default path. `lint` prints
  the scope of every limit, and `netrocket init` writes an example.
* `nr_divert::address`: the pure WinDivert ABI types (`Address`, `Layer`,
  `Param`, `flags`, `pack`) moved out of the `cfg(windows)` module, so they are
  compiled and unit-tested on every platform instead of only on Windows.

### Fixed

* **Deferred re-injection could carry the wrong priority.** `InjectContext`
  sign-extended its 15-bit priority field from bit 15 instead of bit 14, so a
  retained packet packed with `i16::MAX` priority came back as `-1`, and
  `i16::MIN` came back as `0`. Out-of-range priorities are now clamped to the
  representable range instead of wrapping, and the field is masked on the way
  out. Found by running the existing test on Windows for the first time: the
  test itself asserted that the whole `i16` range fits in a 16-bit word that
  also carries the direction, which cannot hold.
* **The test suite now runs on Windows in CI** and on Linux for everything that
  is not Windows-only, which is how the defect above surfaced.
* **CI never ran.** The workflow's step name contained an unquoted colon, so
  GitHub rejected the whole file and every run failed at start-up with no jobs.

## 0.2.0 — 2026-11-08

Closes the attribution gap, makes the Windows backend verifiable, and adds the
diagnostics needed before a first real run.

### Added

* **Start-up endpoint snapshot.** Before the network handles open, attribution is
  seeded from `GetExtendedTcpTable`/`GetExtendedUdpTable` (IPv4 and IPv6, TCP and
  UDP). Connections that predate the daemon are attributed immediately instead of
  never; listeners and UDP rows become PID-only hints. Decoder is pure and
  unit-tested on every platform (`crates/nr-divert/src/win_snapshot.rs`).
* **`netrocket doctor`.** Platform, driver files, elevation, endpoint table and
  configuration in one read-only pass. It opens no WinDivert handle, so it cannot
  divert a packet.
* **Unattributed-traffic diagnostics.** The run loop prints the first eight
  tuples it could not attribute, with packet and byte counts, once per report.
* `docs/WINDOWS-BRINGUP.md` — the ordered checklist of what only hardware can
  settle, with a pass criterion for each step.
* Two attribution regression tests that store a tuple the way a FLOW event does
  and look it up the way a packet does.
* `dist/netrocket-0.2.0-windows-x64.zip` — a cross-compiled x64 binary
  (`x86_64-pc-windows-gnu`, PE32+, 532 KB, no static WinDivert import) shipped
  with a README, a starting config, the driver install script and
  `BUILD-INFO.txt`. **It has never been run on Windows**; see `LIMITATIONS.md`.

### Changed

* **WinDivert is loaded at run time** (`LoadLibraryW` + `GetProcAddress`) instead
  of being a link-time import. A build no longer needs an import library, and a
  missing DLL now prints `WinDivert.dll was not found; run
  scripts/install-windivert.ps1` instead of raising a Windows loader dialog.
  Error 126 (not found) and 193 (wrong architecture) are named in the message.
* `DivertError::with_note` reclassifies a recovery hint as an open failure, so
  the actionable sentence is the one that reaches the user.

### Fixed

* **`run --monitor` would have taken the machine off the network.** The receive
  handle was opened without `WINDIVERT_FLAG_SNIFF`, which makes the driver
  *withhold* matching packets until they are injected back. `sniff` is now a
  required argument to `Interceptor::open`, with a test for each mode.
* **`crates/nr-divert/src/win.rs` did not compile.** It referenced
  `nr_core::Resolver` instead of `nr_core::identity::Resolver`, which is what
  "written against the header but never type-checked" looks like. The Windows
  target is now checked and linted in CI.
* Attribution hashed the PID into the slot index while lookups carried
  `pid = 0`, so *every* lookup missed. The hash now covers the 5-tuple only and
  is endpoint-order independent; the test that catches it builds a real packet.
* UDP snapshot rows were dropped by a listener filter that only makes sense for
  TCP, silently losing every UDP endpoint.
* `bench` sized its hot frame set from `--frames`, so it streamed 45 MB per
  repetition and measured the VM's memory bandwidth (18 Mpps one day, 6 Mpps
  another). The set is now a constant 98 KB, printed in the output, with a test.
* `simulate` flushed retained packets at `u64::MAX/4`, reporting a longest wait
  of 4611686016922 ms. It flushes at the end of the simulated interval instead.

### Changed

* `nr_divert::win` is split into pure cross-platform types (`win::types`,
  `win::pack`) plus a thin FFI layer, so the ABI decisions are testable
  everywhere and the FFI surface is ten functions.
* Separate `RECV_ONLY` and `SEND_ONLY` handles: a retained packet stores a 16-bit
  injection context instead of an 80-byte `WINDIVERT_ADDRESS` taken from a
  receive buffer that has since been reused.
* `Resolver::resolve` returns an owned `String` (the Windows implementation
  builds the name from a temporary wide-char buffer).
* `bench` prints best **and** median; published figures in
  `docs/BENCHMARKS.md` were replaced, not quietly kept.

## 0.1.0 — 2026-11-08

First working tree: pure core (parser, canonical flow keys, compiled rules,
GCRA rate control, bounded retention), WinDivert backend skeleton, simulator,
benchmark, CLI, configuration, and 91 tests including three allocation-counting
proofs.
