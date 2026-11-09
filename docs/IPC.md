# The control channel

How a local program — a UI, a script, a monitoring tool — reads what a running
daemon is doing, without touching the network stack and without a second copy of
the engine.

Start it with `netrocket run --ctl=PATH`. On Windows `PATH` is a pipe name
(`netrocket` becomes `\\.\pipe\netrocket`); elsewhere it is a Unix domain socket
path. If the channel cannot be created the daemon refuses to start rather than
running without the control the user asked for.

## What it is

* **Read-only.** `STATUS` and `LIMITS` report; nothing changes a limit. This is
  a deliberate first step, not an oversight — see *Why read-only* below.
* **Local only.** The Unix socket is mode `0600`; the Windows pipe carries an
  explicit DACL that grants the current user and nobody else, plus
  `PIPE_REJECT_REMOTE_CLIENTS`.
* **Versioned.** A client says `HELLO 1` first. A mismatched client is told the
  version and disconnected instead of being fed a format it cannot parse.
* **Off the packet path.** The packet loop never blocks on a client: it drops a
  fresh `Snapshot` (a `Copy` struct) into a mutex once per second and moves on.

## Wire format

One frame is a 4-byte big-endian length, then that many bytes of UTF-8. Frames
are capped at 16 KiB (`MAX_FRAME`) and the cap is checked *before* allocating, so
a hostile client cannot ask for a gigabyte. Empty frames, oversized frames, and
frames that are not UTF-8 are errors: the connection is dropped, the channel
keeps serving.

Requests are one line. Responses are one line, except `LIMITS`.

| Request | Response | Then |
| --- | --- | --- |
| `HELLO <version>` | `OK netrocket <crate-version> proto 1` | keep open |
| `HELLO <wrong>` | `ERR version <n> unsupported, want 1` | close |
| `STATUS` | `OK packets <n> bytes <n> dropped <n> flows <n> retained <n> marked <n>` | keep open |
| `LIMITS` | `OK <count>` then one `<name> <rate_bps> <burst_bytes> <policy> <scope>` per line | keep open |
| `QUIT` | `BYE` | close |

Anything else is answered with `ERR unknown <request>`, where the echo is
reduced to printable ASCII and truncated to 64 characters — a client learns that
the daemon heard it, and cannot smuggle terminal escapes into a log.

```
client: HELLO 1
  server: OK netrocket 0.2.0 proto 1
client: STATUS
  server: OK packets 1200 bytes 900000 dropped 3 flows 12 retained 4096 marked 0
client: LIMITS
  server: OK 1
          chrome.exe 1000000 65536 ecn process
client: QUIT
  server: BYE
```

## Why read-only

Changing a limit while the daemon runs means the packet thread and the control
thread would share the engine. The engine is deliberately single-owner: no lock,
no atomic, nothing on the hot path. Putting a mutex there to satisfy a UI would
trade the property the whole project is about for a convenience.

The honest alternatives were: a channel that can only lie about changing things,
or a channel that reports truthfully and says what it does not do yet. This is
the second. Mutating requests arrive with hot rule reload, where the engine
already has to swap its configuration safely.

## What one connection costs

Connections are served one at a time. That is correct for the intended client —
a UI that opens one connection and sends `STATUS` on a timer — and it means
there is exactly one state machine to reason about. The cost is stated plainly:
a client that connects and then goes silent holds the channel until it
disconnects. There is no read timeout, because a timeout would also evict the
well-behaved UI that polls every second.

## What is tested, and what is not

Tested on every platform (`cargo test -p nr-app`):

* the exact text of every response, including the version refusal;
* a client that disconnects in the middle of a frame — the channel reports it
  and serves the next client;
* oversized, empty, truncated, and non-UTF-8 frames;
* control characters in an unknown request never reach the response;
* a real Unix-socket round trip: bind, connect, four requests, four responses,
  `BYE`, socket mode `0600`.

Not tested anywhere: the Windows named-pipe path. It needs Windows, and this
sandbox has none. It is written against the documented Win32 signatures, is
type-checked by the Windows target in CI, and is named in `LIMITATIONS.md`
alongside the other things this project has not executed.
