# Raqib and REA, measured

This document compares Raqib with [`morluto/rea`](https://github.com/morluto/rea)
(REA 6.8.0, MIT) on the machine described below. Every number was produced by
running the commands shown, not estimated.

## The machine

```
platform : linux 6.1.158+ (x64)
cores    : 2
memory   : 3.8 GiB
node     : v22.22.3
npm      : 10.9.8
```

Both tools run on the same Node runtime on the same machine, in the same
session, minutes apart.

## Install footprint

| | REA | Raqib |
|---|---|---|
| npm tarball | 6.28 MB (`rea-agents-6.7.0.tgz`) | — |
| installed size | **139 MB** (`node_modules`, 161 packages) | **224 KB** (one file) |
| runtime dependencies | 35+ (ajv, zod, ws, pino, openpgp, @babel/parser, …) | **0** |
| install time | 10.0 s | `npm install` for dev tooling only |
| network at run time | package acquisition, agent setup | **none** |

```bash
npm install rea-agents --no-audit --no-fund --ignore-scripts
# real 0m10.034s → 139M in 161 packages
```

Raqib's 224 KB includes the web console, the three typefaces and the MCP
server. There is nothing to fetch when it runs.

## Startup

```bash
node node_modules/rea-agents/scripts/rea.mjs --version
node dist/raqib.mjs version
```

| | median of 5 runs | best |
|---|---|---|
| REA | **1 034 ms** | 970 ms |
| Raqib | **52 ms** | 49 ms |

**≈ 20× faster to start.** For an MCP server this is the number that decides
whether a tool feels instant or sluggish: the server is spawned on every
agent session.

## The same question, asked of the same application

A 249 KB Electron application (a `package.json`, a main process, a preload
script, an HTML file and a 200 000-character bundle):

```bash
node node_modules/rea-agents/scripts/rea.mjs analyze-javascript-application /tmp/electron-fixture --json
node dist/raqib.mjs js /tmp/electron-fixture --json
```

| | REA | Raqib |
|---|---|---|
| wall clock | **8 253 ms** | **68 ms** |
| output size | **27.2 MB** | **3.2 KB** |
| output shape | `normalized_result` alone is 26.5 MB | facts, locations, limitations |

REA's `normalized_result` inlines the whole bundle it read. Raqib reports the
module graph, the IPC inventory and the limits of the scan — and leaves the
file contents to the caller, which can ask for them.

The size difference matters twice: once for the disk, and once for the
agent's context window, where every kilobyte of a tool result is a kilobyte
the model has to read before it can think.

## What each one can see

REA is the larger project, and it covers ground Raqib does not yet: Ghidra,
IDA, Hopper and JEB bridges, live process capture, Frida, Android devices
over ADB, WASM, EVM bytecode, firmware, network captures, .NET assemblies,
SQLite, PyInstaller archives, Deno binaries, and more.

Raqib covers a smaller surface on purpose, and covers it *without installing
anything*:

| | REA | Raqib |
|---|---|---|
| ELF / PE inspection | via external tools | built in, byte-level |
| JavaScript application analysis | built in | built in |
| ASAR archives | built in | built in |
| Chromium fork mapping | not a dedicated tool | `inspect_chromium_tree` |
| Installed browser identification | not a dedicated tool | `identify_browser` |
| External analysis engines | Ghidra, IDA, Hopper, JEB, Rizin, objdump | not yet |
| Live instrumentation | Frida, process capture, ADB | not planned in 0.1 |
| Evidence identity | digest-based, versioned | content hash, stable |
| Explicit limitations | yes | yes, on every record |

## The design difference

REA is a large system with providers, bridges, sessions, retained dossiers and
a plugin ecosystem. That is the right shape for a research platform and the
wrong shape for a tool you want to start in 50 ms on a machine with no
network.

Raqib's rules are narrower:

1. **Zero runtime dependencies.** Everything is parsed in-process, byte by byte.
2. **No network, ever.** Not for setup, not for assets, not for updates.
3. **One file.** The console, the fonts and the server are inside the bundle.
4. **Evidence or nothing.** An answer without locations and limitations is
   not returned.
5. **Never execute the target.** Static analysis only; runtime behaviour is
   somebody else's tool.

## Reproducing these numbers

```bash
# REA
npm install rea-agents --no-audit --no-fund --ignore-scripts
du -sh node_modules
node node_modules/rea-agents/scripts/rea.mjs --version   # time it

# Raqib
npm run build
du -h dist/raqib.mjs
node dist/raqib.mjs version                             # time it
node bench/bench.mjs                                    # the full harness
```

`bench/bench.mjs` writes `bench/results.json` with the raw samples.
