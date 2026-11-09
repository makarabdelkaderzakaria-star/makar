# Roadmap

Ordered by what actually blocks the next useful release, not by novelty.
Anything here is a plan, not a claim.

## 0.2.0 — what exists today

* [x] Core pipeline: zero-copy parser, canonical flow keys, cached rule
      attribution, GCRA rate control, bounded retention.
* [x] Per-application limits with `shape` / `drop` / `drop-inbound` policies.
* [x] Rule language: protocol, direction, port ranges, CIDR, process name.
* [x] Config file with atomic, flushed saves; `init`, `check`, `lint`.
* [x] Simulator + benchmark, runnable on any OS.
* [x] 91 tests including three allocation-counting proofs.
* [x] WinDivert backend written against the 2.2 header (sync path).

## 0.2 — make it real on Windows (in progress)

Done while working on 0.2:

* [x] **The Windows target is type-checked.** `cargo clippy --target
      x86_64-pc-windows-msvc -D warnings` runs in CI on a Linux runner. This
      immediately caught a real defect: the first draft of `win.rs` did not
      compile at all (`nr_core::Resolver` instead of
      `nr_core::identity::Resolver`), so "written against the header" had been
      an untested claim.
* [x] FLOW watcher wired into the runner on its own thread, with attribution
      shared through one `Mutex` and swept on the slow tick.
* [x] Attribution moved into `nr-core` (`FlowAttribution`) so the whole policy
      is unit-tested on Linux: canonical keys, reverse direction, endpoint-id
      and PID lookups, TTL expiry, table-full behaviour, PID reuse.
* [x] ABI decisions extracted into pure, cross-platform types
      (`win::types`, `win::pack`) with compile-time size/offset assertions, so
      the bitfield map and the flow-data offsets are tested everywhere.
* [x] Separate `RECV_ONLY` / `SEND_ONLY` handles, removing the "which address
      belonged to this retained packet" bug class; deferred packets carry a
      16-bit injection context instead of an 80-byte address.
* [x] Fixed a defect that would have taken machines off the network:
      `run --monitor` opened the receive handle **without**
      `WINDIVERT_FLAG_SNIFF`, which diverts and withholds traffic instead of
      copying it. `sniff` is now a required argument plus two tests.

Still open:

* [ ] **Bring-up on Windows.** First real run: confirm the driver accepts our
      re-injected packets, that our parser and `WinDivertHelperParsePacket`
      agree on the same frames, and that `WINDIVERT_DATA_FLOW` offsets match a
      live event.
* [x] Shrink the attribution blind spot: the start-up snapshot
      (`GetExtendedTcpTable`/`GetExtendedUdpTable`) is implemented, its decoder
      is unit-tested on every platform, and the simulator exercises the same
      seeding path end to end.
* [x] A diagnostic that names what we could *not* identify: the run loop prints
      the first eight unattributed tuples with packet and byte counts.
* [x] `netrocket doctor`: platform, driver files, elevation, endpoint table and
      configuration in one read-only pass that diverts nothing.
* [x] `docs/WINDOWS-BRINGUP.md`: the ordered checklist of what only hardware
      can settle, with a pass criterion per step.
* [x] **CI actually runs.** The workflow file had an unquoted colon in a step
      name, so GitHub rejected it and every run failed at start-up with zero
      jobs — the pipeline had never executed. Fixed, and the run logs are
      mirrored into check-run annotations so a failure is diagnosable without a
      browser.
* [ ] One-command installer: fetch the signed WinDivert binaries, verify the
      signature, place them next to the executable, register the driver.
      (`scripts/install-windivert.ps1` exists and refuses unsigned binaries; it
      has never been run.)
* [x] `cargo test` on a real Windows runner. It runs, and it immediately caught
      the deferred-reinjection priority defect recorded in `CHANGELOG.md`.
* [ ] Run `docs/WINDOWS-BRINGUP.md` steps 1–5 and publish the results,
      including the retransmission count from step 5.

## 0.3 — measure honestly on hardware

* [ ] Latency and throughput with `iperf3`, shaped and unshaped, at 10/100/1000
      Mbit/s, with the driver's own queue-drop counters alongside ours.
* [ ] Publish the retransmission count with and without shaping — this is the
      number that proves the "wastes no bandwidth" claim or refutes it.
* [ ] Batched `RecvEx` behind a flag, with the `ERROR_IO_PENDING` handling
      written and tested before it becomes a default.

## 0.4 — features people will actually ask for

* [x] Per-flow (not just per-process) limits: a browser with one tab on a 4K
      stream no longer starves its own DNS. `limit <name> = <rate> per-flow`,
      with unit tests for independence, for the unchanged default, for
      single-flow enforcement, and for emission charging only the flow that
      emitted.
* [ ] Time-of-day schedules and temporary boosts ("full speed until I am done").
* [ ] Data caps: a byte budget per day/month, which is what metered connections
      need far more than a rate limit.
* [ ] CoDel-style queue management for the "no limit configured but the link is
      congested" case — complementary to GCRA, not a replacement.
* [ ] ECN marking instead of dropping, where the peer supports it.

## 1.0 — interface

* [ ] Local IPC so a GUI or another tool can query and change limits without
      restarting: Windows named pipe with an explicit DACL, length-prefixed
      frames, versioned. The original's pipe grants `BuiltinUsers` ReadWrite;
      that is broader than necessary and will not be copied.
* [ ] Hot rule reload without dropping flows.
* [ ] A real TUI (the current status display is deliberately line-based).

## Explicitly not planned

* Telemetry, crash reporting, or any outbound connection that the user did not
  ask for.
* Bundling or vendoring the WinDivert driver into this repository.
* Multi-user or client/server shaping beyond this machine.
* A WPF-style UI. If a GUI is wanted, it talks to the IPC, it is not the engine.
