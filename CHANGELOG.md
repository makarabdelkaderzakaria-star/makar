# Changelog

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
