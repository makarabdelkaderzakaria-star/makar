# Configuration reference

One plain-text file, default path `netrocket.conf`.

```bash
netrocket init                 # write a commented starting point
netrocket check                # parse and validate
netrocket lint                 # show limits and rules as the engine compiled them
netrocket doctor               # can this machine run `run`? (diverts nothing)
```

Three verbs and one expression syntax. Everything after `#` is a comment.

## `param key = value`

| Key | Default | Meaning |
|---|---|---|
| `queue-length` | `1024` | WinDivert queue, in packets (driver default 4096) |
| `queue-time` | `400ms` | WinDivert queue time (driver default 2000 ms) |
| `queue-size` | `1mb` | WinDivert queue memory (driver default 4 MB) |
| `retain-budget` | `2mb` | bytes we may hold while waiting for a rate |
| `max-retain` | `250ms` | hard ceiling on how long a packet may be held |
| `flow-idle` | `120s` | idle time before a flow row is swept |
| `identity-ttl` | `30s` | how long a PID → name mapping is trusted |
| `batch-max` | `64` | packets asked for per receive (clamped to 255) |
| `recv-timeout` | `100ms` | receive wake interval |
| `default-policy` | `shape` | policy for limits that do not set one |
| `dry-run` | `false` | count only, never divert |

Durations accept `ms`, `s`, or a bare number of milliseconds. Sizes accept
`kb`, `mb`, `gb` or a bare number of bytes.

**Why the defaults are lower than the driver's**: a shaper that queues 2 s of
packets is a shaper that causes retransmissions, and a retransmission spends the
bandwidth twice. `250ms` is below the smallest plausible TCP RTO.

## `limit <name> = <rate> [burst <bytes>] [policy <p>] [per-flow] [cap <bytes>/<period>] [schedule <window>]`

```text
limit chrome.exe  = 8mbit   burst 64kb
limit steam.exe   = 20mbit  burst 256kb
limit backup.exe  = 2mbit   burst 32kb policy drop
limit browser.exe = 8mbit   burst 64kb per-flow
limit phone.exe   = 4mbit   burst 64kb cap 20gb/month
limit updater.exe = 20mbit  burst 256kb schedule 22:00-06:00
```

* Rates: `8mbit`, `20mbps`, `512kbit`, `1.5mbit`, or a bare byte/s number.
* `burst`: how much traffic may go at full speed before the limiter bites.
  At least one MTU (1500 B); smaller values are rounded up in the engine.
* `policy`:

| Policy | Behaviour | Bandwidth cost |
|---|---|---|
| `shape` *(default)* | delay packets until they fit | **1×** — nothing is ever retransmitted |
| `drop` | drop over-limit outbound packets | 2× — TCP retransmits them |
| `drop-inbound` | drop over-limit inbound packets | ~1× — the peer sees a zero window and slows down |

* `per-flow` (or `scope flow`): one bucket **per connection** instead of one
  per process. A browser downloading a 4K stream no longer starves its own DNS
  queries, and one saturated transfer cannot take the whole process's allowance.
  The cost is one `u64` in the flow table row that already exists — no second
  table, no allocation. `scope process` is the default and is what every
  previous version did.

### Time-of-day schedules: `schedule <window>`

A limit that only exists during part of the day — the shape of almost every
"do not saturate the line while I am working" rule.

```text
limit backup.exe = 20mbit burst 256kb schedule 22:00-06:00
limit steam.exe  = 4mbit  burst 64kb  schedule 08:00-18:00
```

* The window is `HH:MM-HH:MM`, minutes may be omitted (`8-18`), and the times
  are **UTC** for the same reason caps are.
* `08:00-18:00` is inside one day; `22:00-06:00` wraps midnight. The start is
  inclusive and the end exclusive, so a window that wraps covers `22:00` up to
  and including `05:59`.
* Outside its window the limit does not exist: packets are forwarded
  immediately, nothing is shaped, and **no cap is charged** (a cap on a
  scheduled limit is a budget for the hours it runs, not for the whole day).
* `simulate --at=09:30` pins the clock, so a schedule can be exercised
  deterministically instead of depending on when the test runs. Without
  `--at`, the simulator uses the real clock, like the daemon.
* A zero-length window (`09:00-09:00`) is rejected: it is either a typo or a
  request to disable the limit, and the config file should say which.
* Weekdays are not supported yet; a schedule is the same every day.

### Data caps: `cap <bytes>/<period>`

A rate limit says *how fast*; a cap says *how much*. This is the feature a
metered connection needs — tethering from a phone plan, or a hotel Wi-Fi with a
daily allowance.

```text
limit phone.exe = 4mbit burst 64kb cap 20gb/month
limit guest.exe = 8mbit burst 64kb cap 2gb/day
```

* Periods are `day` (resets at **00:00 UTC**) and `month` (resets on the first
  of the month, 00:00 UTC). UTC is deliberate: local time would need a timezone
  database, and "it resets at midnight UTC" is a smaller surprise than an hour
  nobody can predict.
* The period may be written `cap 20gb/month`, `cap 20gb per month`, or
  `cap 20gb month`. Without a period it is a day.
* Bytes are counted in **both directions** and charged when a packet is
  admitted, not when it is emitted: a packet the retention buffer later sheds
  still counts. Overcounting is the safe direction to be wrong in.
* When the budget is spent, matching packets are dropped with reason `cap`
  until the period rolls over: `netrocket simulate` lists the count under
  `cap`, the daemon's status line and `netrocket tui` include it in the drop
  breakdown, and `netrocket lint` prints the cap and its period.
* The counter is persisted in `<config file>.caps` (for
  `netrocket.conf`, that is `netrocket.conf.caps`) so restarting the daemon does
  not refund a budget that was already spent. The file stores the period stamp
  with the count, so a counter from yesterday cannot be charged to today. A
  crash loses at most the last minute of accounting.
* A cap of `0` is rejected at parse time: it would drop everything forever.
  Remove the `cap` token to disable it.

## `rule <action> : <match>`

First match wins. Actions:

| Action | Effect |
|---|---|
| `allow` | forward, evaluate no further rules |
| `block` | drop matching packets |
| `limit=<name>` | attribute matching flows to a named limit |
| `pass` | keep evaluating (rarely written explicitly) |

Match grammar — all terms optional, space separated, ANDed:

```text
[ tcp | udp | icmp ]
[ in | out ]
[ sport N[-M] ]
[ dport N[-M] ]
[ src A.B.C.D[/len] | src 2001:db8::/32 ]
[ dst A.B.C.D[/len] | dst 2001:db8::/32 ]
[ proc name.exe ]
all     -- explicit wildcard
```

A bare token containing a dot is treated as a process name, so
`rule block : steam.exe` works.

### The one thing that surprises people

A **limit is a bucket**, not a per-process property. `rule limit=chrome.exe : tcp
dport 443` gives *one shared 8 Mbit/s bucket* to every process that matches that
rule. To make a limit belong to one process, say so:

```text
rule limit=chrome.exe : proc chrome.exe
```

`netrocket lint` prints the compiled predicates for exactly this reason, and now
prints each limit's scope too. A `per-flow` limit is the answer when the sharing
is the problem rather than the attribution:

```text
limit browser.exe = 8mbit burst 64kb per-flow
rule limit=browser.exe : proc browser.exe
```

## Complete example

```text
param queue-time   = 400ms
param max-retain   = 250ms
param retain-budget = 2mb

limit chrome.exe = 8mbit  burst 64kb
limit steam.exe  = 20mbit burst 256kb
limit backup.exe = 2mbit  burst 32kb policy drop
limit browser.exe = 8mbit burst 64kb per-flow
limit phone.exe   = 4mbit burst 64kb cap 20gb/month
limit updater.exe = 20mbit burst 256kb schedule 02:00-05:00

rule allow          : proc svchost.exe
rule limit=chrome.exe : proc chrome.exe
rule limit=steam.exe  : proc steam.exe
rule limit=backup.exe : proc backup.exe
rule limit=updater.exe : proc updater.exe
rule block          : udp dport 27015-27050
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | usage error (bad flag, unknown command) |
| 2 | configuration error (bad file, unknown limit, invalid rate) |
| 3 | runtime error (driver could not be opened, send failed) |
