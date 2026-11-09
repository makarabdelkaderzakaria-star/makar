# Reverse-engineering report — OpenNetLimit → NetRocket

This document applies the **REA discipline** (from the user's `morluto/rea`):
every statement is tagged with what kind of statement it is, and anything that
was not verified is marked as such instead of being asserted.

Tags used below:

| Tag | Meaning |
|---|---|
| `[OBS]` | **Observation** — read directly in a file at a pinned commit. Reproducible. |
| `[DER]` | **Derivation** — follows logically from observations (with the reasoning shown). |
| `[INF]` | **Inference** — a judgement call about intent or real-world effect. Not proven. |
| `[UNK]` | **Unknown** — could not be verified in this environment. |
| `[FIX]` | What NetRocket does instead, with the file that implements it. |

Provenance:

| Item | Value |
|---|---|
| Target repository | `SysAdminDoc/OpenNetLimit` |
| Commit analysed | `f26b46cc93887fab6bbeed2091b5d365fa516e2b` |
| Licence of target | MIT (`LICENSE`) |
| Method repository | `morluto/rea` @ `559083be29bd8502a7feefcbe981380b2bbf4cd9` |
| Target runtime | .NET 8 (`global.json` → `8.0.422`), WPF UI, WinDivert 2.2.2 via `SharpDivert` 1.1.0 |
| Native dependency | WinDivert 2.2 — dual **LGPLv3 / GPLv2** |
| Analysis host | Linux x86-64, rustc 1.99.1, 2 vCPU (see `BENCHMARKS.md`) |

> **Method note, stated up front.** `rea`'s own skill file
> (`.agents/skills/reverse-engineer-anything/SKILL.md`) says to *skip* the REA
> agent harness when the target is an ordinary, complete source tree and to use
> normal repository tools instead. The target is exactly that: 171 `.cs` files,
> ~7 719 lines under `src/`, public. So REA was used as a **methodology**
> (provenance, evidence tagging, fail-closed unknowns), not as a running tool.
> Everything below that is tagged `[OBS]` was read in the checkout; there is no
> decompilation, no binary analysis, and no speculation presented as fact.

---

## 1. What the program does `[OBS]`

Per-app bandwidth limiter for Windows. Shape (not just count) traffic by
process, using WinDivert to intercept and re-inject packets.

* `[OBS]` `src/OpenNetLimit.Engine/` — engine (interception, rate limiting,
  monitoring, rules); `src/OpenNetLimit.UI/` — WPF; `src/OpenNetLimit.CLI/`;
  `src/OpenNetLimit.Service/` — Windows service + named-pipe IPC.
* `[OBS]` `THIRD-PARTY-NOTICES.txt` lists Native.WinDivert 2.2.2 and
  SharpDivert 1.1.0.
* `[OBS]` `RESEARCH.md` in the target repo documents build problems (TFM
  mismatch, `Interlocked` on properties, UI coupling).

## 2. The hot path, as written `[OBS]`

One packet, as it flows through `WinDivertInterceptor`:

1. `[OBS]` `WinDivertInterceptor.cs:282` —
   `var delay = _rateLimiter.GetDelay(processId.Value, payloadLength, isOutbound);`
2. `[OBS]` `WinDivertInterceptor.cs:285` — inside the `delay > 0` branch,
   `_rateLimiter.TryConsume(...)` is called and **its boolean result is
   discarded**, then the packet is handed to `_scheduler.Enqueue(...)`.
3. `[OBS]` `WinDivertInterceptor.cs:289` — the non-delayed path calls
   `TryConsume` again, so the packet is charged once either way.
4. `[OBS]` `WinDivertInterceptor.cs:385,398` — `ResolveProcessName` /
   `ResolveProcessPath` each do `Process.GetProcessById(...)`
   (`GetProcessById` + `MainModule` for the path) with **no cache**.
5. `[OBS]` `RuleEngine.cs:86-95` — `Match` takes `lock (_lock)`, runs a LINQ
   `Where(...FirstOrDefault())` over all rules, and returns `?.Clone()`.
6. `[OBS]` `TokenBucket.cs` — `lock (_lock)`, `double _tokens`, separate
   `TryConsume` (line 20) and `GetDelay` (line 34).
7. `[OBS]` `PacketScheduler.cs:27-33` — `new Timer(DrainReady, ...)` then
   `_drainTimer.Change(1, 1)` → a **1 ms** heartbeat.
8. `[OBS]` `PacketScheduler.cs:14-15` — `MaxQueuePerProcess = 512`,
   `MaxDelay = TimeSpan.FromSeconds(2)`; `:38-40` drops when `delay > MaxDelay`;
   `:48` `packetData.ToArray()` per enqueue.
9. `[OBS]` `FlowTracker.cs:57-62` — on lookup miss it builds a **reversed**
   `FlowKey` and retries.
10. `[OBS]` `ProcessRateLimiter.cs:10-16` — the limiter API is keyed by
    `uint processId` only.

## 3. Defects, and what each one costs `[DER]`

### 3.1 Shaping can grant unlimited throughput `[OBS]` + `[DER]`

`GetDelay` and `TryConsume` both mutate `_tokens` under the same lock
(`TokenBucket.cs:20-68`). Between a `GetDelay` returning `delay > 0` and the
following `TryConsume`, nothing prevents the state from changing, and the
branch at `:284` ignores `TryConsume`'s return value entirely.

`[DER]` Consequence: the packet is queued in the scheduler, so a limit *is*
applied in the steady state (the scheduler's delay comes from the same bucket).
But the accounting is not atomic, and a caller cannot rely on the boolean.
`[INF]` In practice this shows up as jitter and occasional bursts above the
configured rate rather than as "limits do nothing"; the honest statement is
**"the check and the commit are separate, and one caller ignores the answer"**,
not "limits never work".

### 3.2 Transmissions caused by the shaper `[OBS]` + `[DER]`

`MaxDelay = 2 s` (`PacketScheduler.cs:15`) with a 512-packet per-process cap
(`:14`) and drop-tail when full (`:54`).

`[DER]` Standard TCP retransmission timers start around 200–300 ms on Windows
and back off exponentially. A packet held for up to 2 s is therefore, by
construction, a packet TCP has **already retransmitted** — so its bytes were
spent at least twice. Drop-tail on a shaping queue has the same effect: the
newest segment is discarded, TCP retransmits, bandwidth is spent twice.

`[INF]` This is the mechanism behind the user's complaint that such tools
"waste bandwidth". It is not the limiting itself; it is the *queueing policy*.

### 3.3 A 1 ms timer that scans every queue `[OBS]` + `[DER]`

`_drainTimer.Change(1, 1)` fires 1 000 times/s regardless of whether anything is
queued; each tick walks every per-process queue and calls `ToArray()` per
enqueue (`:48`) and `Interlocked.Increment` per packet (`:40,54,58,84,88`).

`[DER]` On an idle machine that is 1 000 wakeups/s of pure overhead; on a busy
one it is 1 000 lock acquisitions/s against a queue that the receive thread is
also locking. `[INF]` This is the "heaviness" that is measurable in Task
Manager as constant CPU for a program that is supposed to be idle.

### 3.4 Per-event process resolution `[OBS]` + `[DER]`

Every FLOW event calls `Process.GetProcessById` twice (`:385`, `:398`); the
second one also touches `MainModule`, which opens the process and reads the
image path. `[DER]` Each call is a handle open/close pair plus, for
`MainModule`, a file-system metadata read. `[OBS]` There is no memoisation:
`ResolveProcessName` is a pure `try/catch` around the call.

`[DER]` Additional failure mode: for protected processes the call throws, and
the catch returns `"PID-{processId}"` (`:391`) or `null` (`:401`) — a *string
that looks like a name*. A rule matching on a real name never fires for those
processes, and no diagnostic says so.

### 3.5 Identity is keyed by PID `[OBS]` + `[DER]`

`ProcessRateLimiter` keys buckets by `uint processId` (`:10-16`) while rules
match process *name/path* (`RuleEngine.cs:86-95` → `MatchesProcess`).
`[DER]` Windows recycles PIDs. A limit configured for one process can be
inherited by an unrelated process that obtains the same PID, and
`SetLimit` (`ProcessRateLimiter.cs:28`) reassigns buckets by PID alone.

### 3.6 Flow identity needs a reverse lookup `[OBS]`

`FlowTracker.cs:57-62` retries with a reversed key on miss. `[DER]` That is a
second hash lookup for every inbound packet, i.e. the common case for
downloads.

### 3.7 Rule matching allocates per packet `[OBS]`

`RuleEngine.cs:86-95`: `lock`, then LINQ (`Where` allocates an enumerator and a
delegate), then `Clone()` on the winning rule. `[DER]` At 50 kpps that is 50 000
lock/unlock pairs, 50 000 enumerator allocations and up to 50 000 rule clones
per second — GC pressure on the same thread that must not block.

### 3.8 Corrected claims (things this report does *not* say)

Recorded because earlier drafts of this analysis got them wrong; the file says
otherwise `[OBS]`:

* The IPC pipe **does** have an ACL. `Service/IPC/PipeServer.cs:76-103`
  (`CreateSecurePipe`) grants `BuiltinAdministrators` FullControl and
  `BuiltinUsers` ReadWrite. The finding is the *breadth* of the
  `BuiltinUsers` write grant, not the absence of an ACL.
* `RuleEngine.SaveRules` (157-180) takes a snapshot under the lock and writes
  `filePath + ".tmp"` then `File.Move(..., overwrite: true)`. That is atomic
  against a crash, but it never flushes (`fsync`), so a power loss can leave a
  truncated file. NetRocket adds the flush
  (`crates/nr-app/src/configio.rs::save_atomic`).
* `EngineWorker` does wire `RuleReconciler` to `RuleEngine.OnRulesChanged`, so
  the "rules diverge after an IPC change" hypothesis is **not** established.
  Marked `[UNK]` pending a full IPC-path read; nothing in NetRocket's design
  depends on it.

## 4. What NetRocket changes — one line per defect

| # | Original | NetRocket |
|---|---|---|
| 3.1 | check and commit are separate calls | **one** `Gcra::try_acquire` that tests and commits, `crates/nr-core/src/gcra.rs` |
| 3.2 | 2 s max delay, drop-tail at 512 packets | 250 ms ceiling (below the smallest RTO), byte-budgeted retention, sheds the *stalest* entry, `crates/nr-core/src/scheduler.rs` |
| 3.3 | 1 ms timer walking every queue | no heartbeat at all: the loop blocks on the driver, `scheduler.rs::next_due_ns` gives the exact wake instant |
| 3.4 | `GetProcessById` per FLOW event | per-`ProcKey` cache with negative caching and TTL, `crates/nr-core/src/identity.rs` |
| 3.5 | bucket keyed by PID | limiter lanes keyed by limit, flows keyed by `(5-tuple, PID, start_time)` — a recycled PID is a different identity |
| 3.6 | reverse-key retry | canonical 5-tuple: both directions hash to the same key, `crates/nr-core/src/flow.rs` |
| 3.7 | lock + LINQ + `Clone()` per packet | rules compiled once to flat `Copy` data, name interned to an id, **result cached per flow**, `crates/nr-core/src/rules.rs`, `pipeline.rs` |
| 3.8 | — | temp file + `fsync` + rename, `crates/nr-app/src/configio.rs` |

Two further changes that are not defect fixes but matter for "wastes no
bandwidth":

* `[FIX]` Tokens are charged **when a packet is actually emitted**, not when it
  is queued (`pipeline.rs::on_emitted`). A policy of "delay" therefore really
  delays, and a retained packet that is later shed does not silently consume
  the flow's allowance.
* `[FIX]` The WinDivert filter is passed through (`run --filter=...`) instead of
  always opening with `"true"` as the original does
  `[OBS]` (`WinDivertInterceptor.cs:81-82`). Filtering in the driver is free;
  filtering in user mode is not.

## 5. Unknowns and risks, stated as unknowns

* `[UNK]` **The Windows backend has never run.** It is compiled only on
  `cfg(windows)` and the analysis host is Linux. `crates/nr-divert/src/win.rs`
  follows the header exactly — `WINDIVERT_ADDRESS` is asserted to be 80 bytes
  with the union at offset 16 — but struct bitfields (`Outbound` at bit 17,
  `IPv6` at bit 20) and the `WINDIVERT_DATA_FLOW` offsets are verified by
  reading `windivert.h`, **not** by running. Treat the first Windows run as
  bring-up.
* `[UNK]` End-to-end latency effect of 250 ms retention on interactive traffic
  has not been measured on a real link. The theoretical argument (below RTO)
  is sound but is an argument.
* `[UNK]` Batched `WinDivertRecvEx` (up to `WINDIVERT_BATCH_MAX` = 255) needs
  the overlapped/completion-port path. `win.rs` documents this and does **not**
  enable batching by default; `docs/BENCHMARKS.md` says why.
* `[UNK]` Behaviour when another WinDivert consumer (antivirus, VPN) shares the
  same priority level. The header notes packets are diverted once per priority
  level and that sharing a level has undefined ordering; NetRocket opens at
  priority 0 like the original, so this risk is inherited, not solved.
* `[OBS]` WinDivert is LGPLv3/GPLv2. Distributing NetRocket **with** the driver
  binaries carries notice/relinking obligations; `NOTICE` records them. Reading
  `windivert.h` to write FFI declarations is not a licence event, but shipping
  the DLL/SYS is.

## 6. Reproduction

```bash
# 1. the target, pinned
git clone https://github.com/SysAdminDoc/OpenNetLimit
cd OpenNetLimit && git checkout f26b46cc93887fab6bbeed2091b5d365fa516e2b

# 2. verify each observation above, e.g.
sed -n '282,291p' src/OpenNetLimit.Engine/Interception/WinDivertInterceptor.cs
sed -n '86,95p'   src/OpenNetLimit.Engine/Rules/RuleEngine.cs
sed -n '27,60p'   src/OpenNetLimit.Engine/RateLimiting/PacketScheduler.cs
sed -n '76,103p'  src/OpenNetLimit.Service/IPC/PipeServer.cs

# 3. NetRocket's side
cargo test                 # 88 tests, including the behavioural ones
cargo run --release -- bench
```
