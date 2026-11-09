# Architecture

Raqib is one program in four layers. Nothing below the top layer knows about
MCP, and nothing in the core layer knows about HTTP.

```
  src/cli.ts          the command line: argument parsing, output shaping
  src/mcp/server.ts   JSON-RPC 2.0 over stdio, one tool per capability
  src/web/server.ts   a local HTTP server for the console
        │
        ▼
  src/core/*          the analysis engine: parsers, scanners, indexers
        │
        ▼
  src/core/util.ts    walking, hashing, classification, formatting
```

## The core

| Module | Responsibility |
|---|---|
| `core/elf.ts` | ELF32/ELF64, both endiannesses: sections, segments, symbols, dynamic dependencies, GNU build id, PIE/NX/RELRO |
| `core/pe.ts` | PE32/PE32+: sections, imports, exports, Authenticode certificate table, ASLR/DEP/CFG |
| `core/js.ts` | a JavaScript lexer that masks strings, comments, template literals and regex literals before matching; module edges, Electron APIs, IPC channels, `webPreferences` switches, source maps |
| `core/asar.ts` | the Electron archive format, written from the specification rather than by shelling out to `asar` |
| `core/indexer.ts` | tree inventory: counts, sizes by language, largest files, notable manifests |
| `core/search.ts` | content search over a tree, with a worker pool |
| `core/searchWorker.ts` | the worker half of the search, reading files in parallel |
| `core/chromium.ts` | Chromium-family trees (subsystems, GN arguments) and installed browsers (product, version, feature markers) |
| `core/strings.ts` | printable string recovery, ASCII and UTF-16LE |
| `core/evidence.ts` | the Evidence record and its content-derived identity |
| `core/util.ts` | the directory walk, file classification, hashing, formatting |

## Why a lexer and not a regex sweep

A naive JavaScript scanner matches `import 'x'` inside a comment, or
`require('y')` inside a string, and then reports a dependency that does not
exist. Raqib masks the non-code regions first:

```
maskSource()      one pass, skipping comments, '…', "…", `…` and /…/
   ↓
index of masked ranges
   ↓
indexOf('import')  →  check the candidate is code  →  read the specifier
```

`maskSource` also decides whether a `/` starts a regular expression or is a
division, by looking at the previous significant token. It is the difference
between a tool that can be trusted on a minified bundle and one that cannot.

## Why the search has workers

A Chromium checkout is tens of thousands of files. Reading them one at a time
on the main thread is dominated by waiting on the filesystem, so:

1. the tree is walked once, and files that cannot contain text are dropped;
2. the list is split into chunks, one per worker thread;
3. each worker reads its files **in parallel** (24 at a time) and scans them;
4. results are merged and sorted by file, then line.

On the benchmark machine this cut a 2 000-file search from 634 ms to 342 ms.
Case-sensitive literal searches also pre-filter with `Buffer.includes`, so a
file that does not contain the bytes is never decoded.

## Evidence identity

`makeEvidence` hashes the substance of a record — kind, subject, summary,
facts with their sources, locations, metrics, limitations — and not the wall
clock. Analysing the same target twice produces the same `ev_…` id, so an
agent can compare two runs by comparing ids, and a stored answer stays
recognisable across sessions.

The hash deliberately excludes `generated_at`, which is the only field that
changes between two identical runs.

## The Evidence record

```ts
interface Evidence {
  id: string;            // content hash, stable across runs
  kind: string;          // "elf" | "pe" | "js-application" | …
  subject: string;       // what was analysed
  producer: string;      // "raqib/0.1.0"
  generated_at: string;  // when
  summary: string;       // one paragraph
  facts: Fact[];         // labelled values, each optionally anchored
  locations: SourceLocation[];  // file + line + column, or byte offset
  metrics: Metric[];     // countable things
  limitations: string[]; // what this run could NOT establish
  data?: Record<string, unknown>; // machine payload
}
```

`limitations` is not decoration. Every parser in Raqib writes the reasons its
answer is incomplete: a stripped symbol table, an unpacked archive entry, a
signature that was located but not verified, a feature that may have been
compiled out. A reverse-engineering tool that hides its gaps teaches its user
to trust it further than it deserves.

## The MCP layer

`mcp/server.ts` is a JSON-RPC 2.0 responder over newline-delimited stdio:

```
initialize → protocol negotiation, server info, instructions
tools/list → eight tools, each with a JSON Schema
tools/call → the work; the result carries the text rendering *and*
              structuredContent, so a client can pick either
ping, notifications → acknowledged, never answered
```

The session keeps the last 64 Evidence records, so `get_evidence` can fetch a
previous answer by id without re-running the analysis.

Tool results are returned in both channels on purpose: the text channel is
what a model reads, the structured channel is what a program reads.

## The console

`web/server.ts` is a `node:http` server with four routes and no framework.
The interface is three files (`index.html`, `app.css`, `app.ui.js`) inlined
into the bundle as text, plus the three woff2 typefaces inlined as base64 —
which is why the console works with no network and no static file server.

The API is three endpoints: `/api/health`, `/api/analyze`, `/api/search`
(plus `/api/read` for previewing a file). The browser talks to the server with
relative URLs only.

## Build

One esbuild pass produces `dist/raqib.mjs` (the CLI, the MCP server and the
console in one file) and `dist/searchWorker.mjs` (the search worker). The
plugin in `scripts/build.mjs` inlines the UI as text and the fonts as base64.
TypeScript is used for checking only; there is no runtime transpilation.

## Deliberate omissions

- **No plugin system.** A smaller surface is the point.
- **No network client.** Not even for updates.
- **No runtime execution of the target.** Static analysis only.
- **No telemetry.** There is no code path in Raqib that opens a socket.
