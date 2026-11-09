# Raqib — رقيب

**A light, offline reverse-engineering observatory.**
One file, zero runtime dependencies, no network, 52 ms cold start.

Raqib is a from-scratch re-implementation of the ideas in
[`morluto/rea`](https://github.com/morluto/rea) (REA, MIT): an MCP server that
lets an agent inspect binaries, JavaScript applications, Electron archives and
Chromium-family source trees **without executing the target** and **without
reaching the internet**.

It exists because REA is a 139 MB, 161-package installation that takes a
second to start and answers an Electron question with 27 MB of JSON — and
because a reverse-engineering tool that has to phone home before it can look
at a file is not a tool you can trust on an air-gapped machine.

```
  REA   1 034 ms startup · 139 MB installed · 27 MB of JSON for one app
  Raqib   52 ms startup · 224 KB shipped  · 3.2 KB of JSON for the same app
```

Both numbers were measured on the same machine; the method is in
[`docs/COMPARISON.md`](docs/COMPARISON.md).

---

## What it does

| Tool | What it reads | What it proves |
|---|---|---|
| `inspect_binary` | ELF, PE | sections, symbols, imports, exports, build id, hardening flags, strings |
| `analyze_js_application` | JS/TS app trees | module edges, Electron boundaries, IPC channel inventory, unmatched channels |
| `search_code` | any tree | literal or regex matches with file:line:column and context |
| `index_tree` | any tree | file/language/size inventory, notable manifests |
| `inspect_chromium_tree` | brave-core, chromium, forks | which privacy subsystems exist, where they live, which GN build arguments are set |
| `identify_browser` | an installed browser | product, version, Chromium version, compiled-in feature markers |
| `read_asar` | `.asar` archives | the manifest, the entry list, the contents of one entry |
| `get_evidence` | this session | a previous answer, by id |

Everything is read-only. Nothing is executed, nothing is installed, nothing is
fetched.

## Install

```bash
git clone https://github.com/makarabdelkaderzakaria-star/raqib
cd raqib
npm install          # development only: typescript + esbuild + fonts
npm run build        # produces dist/raqib.mjs (one file, 224 KB)
npm test             # 40 tests
```

The shipped artifact has **no runtime dependencies**. Node 20.11+ is the only
requirement, and the fonts and interface are inlined into the binary.

## Use it from an agent

```bash
node dist/raqib.mjs setup claude     # or: codex, cursor, gemini
```

`setup` writes the MCP registration into the agent's own configuration file,
takes a backup first, and downloads nothing. Restart the agent afterwards.

## Use it from a terminal

```bash
raqib analyze /usr/lib/brave-browser      # dispatch on what the path is
raqib elf /usr/bin/brave                  # one ELF image, in detail
raqib js /opt/my-app                      # a JavaScript/Electron application
raqib search ./src "contextBridge" -r     # search a tree
raqib chromium ~/src/brave-core           # map a Chromium fork
raqib browser /opt/google/chrome          # identify an installed browser
raqib strings ./brave --max 200           # recover strings from a binary
raqib asar ./app.asar                     # read an Electron archive
raqib index .                             # what is in this directory
raqib doctor                              # what this machine can do
```

Add `--json` for machine-readable output, `--out file.json` to write it to a
file.

## Use it as a console

```bash
raqib serve --port 8787
```

Opens a local, single-page console: give it a path, get facts, locations and
an explicit list of what could **not** be proven. The interface, the three
typefaces and the server are all inside the binary — it never fetches an
asset, which is why it works on a machine with no network.

## Publish your own copy

Raqib is meant to be forked. One command turns this tree into a standalone
repository under a new name, with its own history:

```bash
./scripts/publish-repo.sh my-raqib          # or: my-raqib private
```

It stages a clean copy (no `node_modules`, no `dist`), commits it, creates
`<your-account>/my-raqib` and pushes. You need the GitHub CLI with permission
to create repositories; nothing else is contacted.

## The Brave / Chromium workflow

The flagship case this was built for: understanding what a Chromium fork
actually ships.

```bash
raqib chromium ~/src/brave-core
```

prints the subsystems the tree implements — fingerprinting protection, Shields,
tracker blocking, debouncing, Tor, Rewards, the AI assistant, sync — each
with the files that implement it, plus the GN build arguments that switch them
on, plus the limits of the scan.

```bash
raqib browser /usr/lib/brave-browser
```

identifies an *installed* browser from its own bytes: the product and version
come from the version markers inside the executable, and the feature list comes
from the strings the build compiled in — not from a file name or a registry
key that could lie.

## The Evidence model

Every answer is an Evidence record:

```jsonc
{
  "id": "ev_b9acc95c2b373bc0",      // content hash: the same target gives the same id
  "kind": "elf",
  "subject": "/bin/ls",
  "summary": "ELF64 x86-64 ET_DYN image with 31 sections …",
  "facts":     [ { "label": "elf.needed", "value": "libselinux.so.1, libc.so.6" } ],
  "locations": [ { "file": "src/main.js", "line": 14, "column": 11 } ],
  "limitations": [
    "The symbol table was stripped: only dynamic symbols remain, so internal function names cannot be recovered."
  ]
}
```

The `limitations` array is the point. A reverse-engineering tool that only
reports what it found is indistinguishable from one that guesses. Raqib prints
the gaps next to the facts, and the console stamps the answer when a run had
none.

## Documentation

| File | What is in it |
|---|---|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | how the tool is built, module by module |
| [`docs/MCP.md`](docs/MCP.md) | the MCP surface: tools, schemas, a real session |
| [`docs/COMPARISON.md`](docs/COMPARISON.md) | REA and Raqib side by side, with the measurements |
| [`docs/DESIGN.md`](docs/DESIGN.md) | the console's design system |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | what is next, and what is deliberately not planned |
| [`LIMITATIONS.md`](LIMITATIONS.md) | everything this tool cannot do, in one place |

## Licence

MIT — see [`LICENSE`](LICENSE). Raqib is an independent implementation; no
code was copied from REA or from brave-core. The inspiration is credited in
[`NOTICE`](NOTICE).
