# Windows bring-up checklist

The backend compiles and lints for `x86_64-pc-windows-msvc` and its ABI
decisions are unit-tested on every platform, but **it has never run on
Windows**. This is the list of things to verify in order, with what each one
proves and how to tell that it passed. Work top to bottom; each step assumes the
one above it passed.

Run everything from an **elevated** PowerShell, in the folder with
`netrocket.exe`.

## 0. Preflight

```powershell
.\netrocket.exe doctor
```

Expected: `driver files` ok, `elevation` ok, `endpoint table` ok, `configuration`
ok, and the final line "all checks passed".

| If it fails | Meaning |
|---|---|
| `driver files — missing: WinDivert.dll` | run `scripts\install-windivert.ps1` |
| `elevation — no interactive session` | start PowerShell with Run as Administrator |
| `endpoint table — GetExtendedTcpTable(...) failed: 5` | not elevated, or a hardened policy blocks the call |

`doctor` opens **no** WinDivert handle. If it passes, nothing has been touched.

## 1. Does the driver open at all?

```powershell
.\netrocket.exe run --monitor --filter="tcp and tcp.DstPort == 443"
```

Expected within a second:

```
netrocket 0.2.0 — monitoring, nothing is diverted (filter: tcp and tcp.DstPort == 443)
attribution: seeded N established endpoints, M listeners/PID hints, 0 skipped
<tick> bytes flows ... unattributed 0
```

**What this proves:** `WinDivertOpen` works, `--monitor` really passes
`WINDIVERT_FLAG_SNIFF` (browsing must stay perfectly normal — if the network
freezes, the flag is wrong and that is the bug to fix first), the start-up
snapshot calls `GetExtendedTcpTable` successfully, and the statistics tick runs.

**Pass criterion:** you can browse the web normally for 30 s; `unattributed`
stays 0 for HTTPS traffic that existed before start-up.

## 2. Does attribution name real processes?

With the same command running, open a page in a browser.

Expected: `unattributed 0` and, if you add `--filter="tcp"`, flows keep being
counted. Behind the scenes each new flow arrives as a FLOW event, is resolved to
`(pid, start_time)` and then to a name.

**What this proves:** `QueryFullProcessImageNameW`, the FLOW-layer struct
offsets (PID at union offset 16), and the canonical-key agreement between a FLOW
event and a network packet.

**If it fails:** `unattributed` climbs and the diagnostic block lists tuples.
That means FLOW events are not matching packets — check `WINDIVERT_DATA_FLOW`
offsets against `windivert.h` on the machine, and whether `EndpointId` aliasing
is needed (`FlowEvent::protocol` at offset 56, ports at 52/54).

## 3. Does re-injection work, and does shaping actually delay?

Start a large download, then:

```powershell
.\netrocket.exe run --config=netrocket.conf
```

with a limit that is *half* your real speed, e.g. `limit chrome.exe = 20mbit` on
a 50 Mbit/s line, and rule `rule limit=chrome.exe : proc chrome.exe`.

Expected: the download settles near the configured rate; `held` shows non-zero
bytes; drops stay near zero (`shape` policy delays rather than drops).

**What this proves:** the separate `SEND_ONLY` handle accepts our packets, the
`InjectContext` direction is right (wrong direction = packets vanish or loop),
and the GCRA is actually clamping.

**Pass criterion:** the download does not fail or restart, and
`Get-NetTCPConnection` still shows the connection established throughout.
A connection that dies here means re-injected packets are malformed.

## 4. Cross-check our parser against the driver

The riskiest remaining assumption is that our zero-copy parser agrees with the
driver's view of each frame. To check it, temporarily log disagreements:

* add a debug build that calls `WinDivertHelperParsePacket` for every frame and
  compares `ppIpHdr.Protocol`, `ppTcpHdr->SrcPort/DstPort` and `pDataLen` with
  `PacketView`'s values;
* run it with `--monitor` for a minute under mixed TCP/UDP/IPv6 traffic.

**Pass criterion:** zero mismatches. Any mismatch is a bug in
`nr-core::packet`, which is the one place where a silent error would
mis-attribute traffic instead of crashing.

## 5. Measure the things this repo could not measure

Only after 1–4 pass is a throughput number meaningful:

```powershell
# 30 s with and without shaping, then compare
iperf3 -c <host> -t 30
```

Record: achieved Mbit/s, `retained_peak`, `dropped_total`, and — the number that
matters for the "wastes no bandwidth" claim — **TCP retransmissions** from
`Get-NetTCPConnection` / `netstat -s`. Then fill in `docs/BENCHMARKS.md`,
keeping the current note that the existing figures are Linux-pipeline numbers.

## Known unknowns this checklist is testing

| Assumption | Verified by |
|---|---|
| `WINDIVERT_ADDRESS` bitfield positions (`Outbound` = bit 17) | steps 1–2 (a wrong direction freezes traffic) |
| `WINDIVERT_DATA_FLOW` offsets (PID 16, ports 52/54, protocol 56) | step 2 |
| `WINDIVERT_MTU_MAX` buffer size is enough | any step; a truncated frame shows in `parse_errors` |
| Separate `SEND_ONLY` handle is accepted for re-injection | step 3 |
| `GetExtendedTcpTable` row layouts (v4/v6, TCP/UDP) | step 1, `seeded N` must be plausible against `netstat -ano` |
| Port field is big-endian in the low half of the `DWORD` | step 1: compare seeded tuples with `netstat -ano`; a byte-swapped port would attribute nothing |

## If something goes wrong

* `netrocket run` freezes the network → immediately `Ctrl-C`; if that does not
  work, `sc stop windivert`. Then check the `SNIFF` flag path first.
* Everything drops → the `SEND_ONLY` handle probably failed to open; the run
  loop logs `send_failures`.
* Nothing is limited → run `netrocket lint` and check that a `rule` references
  the limit (a limit alone applies to nothing), and `netrocket doctor` for the
  "limits unused" note.
* Unattributed traffic → step 2. Until it is fixed, that traffic is forwarded
  untouched, which is the intended fail-closed behaviour.

Report back with: the exact commands, the first 20 lines of output, and
`netstat -ano | findstr <port>` for one affected flow.
