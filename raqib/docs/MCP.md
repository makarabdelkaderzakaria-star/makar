# The MCP surface

Raqib speaks MCP over stdio: newline-delimited JSON-RPC 2.0.

```bash
node dist/raqib.mjs mcp
```

Register it with an agent:

```bash
node dist/raqib.mjs setup claude    # ~/.claude.json
node dist/raqib.mjs setup codex     # ~/.codex/config.toml
node dist/raqib.mjs setup cursor    # ~/.cursor/mcp.json
node dist/raqib.mjs setup gemini    # ~/.gemini/settings.json
```

`setup` backs the file up (`<file>.bak-<timestamp>`) before writing and
downloads nothing.

## A real session

```
→ {"jsonrpc":"2.0","id":1,"method":"initialize",
   "params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"claude-code","version":"1.0"}}}
← {"jsonrpc":"2.0","id":1,"result":{
    "protocolVersion":"2025-06-18",
    "capabilities":{"tools":{"listChanged":false}},
    "serverInfo":{"name":"raqib","version":"0.1.0"},
    "instructions":"Raqib inspects binaries … without executing the target."}}

→ {"jsonrpc":"2.0","method":"notifications/initialized"}          (no reply)

→ {"jsonrpc":"2.0","id":2,"method":"tools/list"}
← {"jsonrpc":"2.0","id":2,"result":{"tools":[…]}}

→ {"jsonrpc":"2.0","id":3,"method":"tools/call",
   "params":{"name":"inspect_binary","arguments":{"path":"/bin/ls"}}}
← {"jsonrpc":"2.0","id":3,"result":{
    "content":[{"type":"text","text":"# elf — /bin/ls\n…"}],
    "structuredContent":{
      "evidence_id":"ev_b9acc95c2b373bc0",
      "normalized_result":{ … }}}}
```

Protocol negotiation: the server answers with the client's requested version
when it is one it knows (`2024-11-05`, `2025-03-26`, `2025-06-18`), and with
`2025-06-18` otherwise.

Notifications never produce a reply. Unknown methods produce a JSON-RPC error,
never a crash.

## The tools

### `inspect_binary`

```jsonc
{ "path": "/abs/path", "strings": true, "maxStrings": 2000 }
```

Reads an ELF or PE image. Returns the header identity, sections, symbols,
imports, exports, the GNU build id, the Authenticode certificate table, the
hardening flags, and — unless `strings: false` — the printable strings.

*Limitations reported:* a stripped symbol table; a signature that was located
but not cryptographically verified; an image that is neither ELF nor PE.

### `analyze_js_application`

```jsonc
{ "path": "/abs/path/to/app" }
```

Walks a JavaScript/Electron application and reports the package manifest, the
entry point, the module edges, the frameworks in use, the Electron boundary
and the **IPC channel inventory** — channels handled in the main process,
channels invoked or sent from the renderer, and the channels that exist on
one side only. Those unmatched channels are the interesting ones: they are
usually a feature that was half-removed.

*Limitations reported:* files larger than 12 MiB are not scanned; a missing
`package.json` means the entry point is unknown.

### `search_code`

```jsonc
{ "path": "/abs/tree", "pattern": "contextBridge",
  "regex": false, "caseSensitive": false,
  "maxResults": 200, "contextLines": 0 }
```

Literal or regular-expression search across a tree. Returns file, line,
column, the matching line, and optional context lines. Binary files are
skipped; oversized files are skipped.

### `index_tree`

```jsonc
{ "path": "/abs/tree", "maxDepth": 64 }
```

The inventory: file and directory counts, total bytes, bytes per language,
the largest files, the top-level breakdown, and the manifests that usually
matter (`package.json`, `Cargo.toml`, `deps.gn`, `BUILD.gn`, …).

### `inspect_chromium_tree`

```jsonc
{ "path": "/abs/brave-core" }
```

Maps a Chromium-family source tree:

- the **flavour** — brave, chromium, edge, vivaldi, opera or unknown — with
  the evidence for that conclusion;
- the **privacy subsystems** present, each with the files that implement it
  and the files that only mention it;
- the **GN build arguments** that switch those subsystems on, with the file
  and line each one was read from.

### `identify_browser`

```jsonc
{ "path": "/usr/lib/brave-browser" }
```

Identifies an installed Chromium-family browser from its own bytes. The
product and version come from the version markers inside the executable; the
feature list comes from the strings the build compiled in.

*Limitations reported:* a feature compiled out of the build leaves no marker,
so an absent feature is not proof of an absent feature.

### `read_asar`

```jsonc
{ "path": "/abs/app.asar", "entry": "app/main.js" }
```

Without `entry`: the archive manifest — every file, its size, its offset,
whether it is executable or unpacked. With `entry`: that entry's contents.

### `get_evidence`

```jsonc
{ "id": "ev_b9acc95c2b373bc0" }
```

Returns an answer produced earlier in this session. The session keeps the
last 64 records; the id is a content hash, so the same analysis always
produces the same id.

## Result shape

Every tool returns:

```jsonc
{
  "content": [{ "type": "text", "text": "<rendered evidence>" }],
  "structuredContent": {
    "evidence_id": "ev_…",
    "normalized_result": { /* the full Evidence record */ }
  }
}
```

The text rendering is a readable Markdown view: the summary, the facts with
their sources, the locations, and — under `## Not proven` — the limitations.
A client can read either channel; both carry the same facts.
