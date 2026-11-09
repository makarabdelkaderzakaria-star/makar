# Changelog

All notable changes to Raqib are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2.0] — 2026-11-09

### Added

- **Source map resolution** — a version-3 reader with a base64 VLQ decoder.
  It lists the original files a bundle was built from and maps positions in
  both directions: a position in the bundle back to its original file, and an
  original position forward into the bundle. A position on an unmapped line
  falls back to the nearest preceding mapping and is marked approximate.
- **Mach-O reader** — thin and universal binaries: header, load commands,
  segments and sections, dynamic libraries, rpaths, UUID, entry point, symbol
  table and the code signature blob.
- **PE import hashing** — the classic import hash, so a binary can be
  recognised by its imports alone.
- **Evidence diffing** — `compare_analyses` compares two analyses and reports
  the facts that were added, removed and changed, the locations that moved,
  and the gaps that opened or closed.
- **One dispatcher** — `core/analyze.ts` decides how a path is analysed for
  the MCP server, the command line and the console alike.
- **Manifest reader** — a `package.json` is read as structure: the name,
  version, entry point, runtime and development dependencies, scripts,
  binaries, the engines it demands and the Electron version it was built
  against, wherever that version was declared.

### Changed

- The MCP `inspect_binary` tool now understands Mach-O as well as ELF and PE.
- The command line gained `macho`, `map`, `compare` and `manifest`, plus
  `--kind`, `--line`, `--column` and `--source`.
- A `package.json` is now recognised on sight, so `raqib analyze` reports a
  manifest instead of a list of strings.
- A positional argument is now consumed when it is read, so `asar <file>
  <entry>` reads the entry it was given.

### Fixed

- The source map VLQ decoder reported the number of values it read instead of
  the number of characters, which truncated every multi-field segment.
- Mach-O command identifiers above 2^31 were compared as signed integers and
  never matched.
- A positional argument was read but never consumed, so `compare left right`
  compared `left` with itself and `asar file entry` ignored the entry.
- A source map position on a line with no mapping now falls back to the
  nearest preceding mapping and is marked as approximate, instead of
  reporting nothing.

## [0.1.0] — 2026-11-09

The first release: a light, offline reverse-engineering observatory.

### Added

- **ELF reader** — ELF32/ELF64, both endiannesses: sections, segments, symbols,
  dynamic dependencies, GNU build id, and the PIE/NX/RELRO hardening flags.
- **PE reader** — PE32/PE32+: sections, import and export tables, the
  Authenticode certificate table, and the ASLR/DEP/CFG flags.
- **JavaScript scanner** — a lexer that masks strings, comments, template
  literals and regular-expression literals before matching; module edges,
  Electron APIs, IPC channel inventory, `webPreferences` switches, source maps.
- **ASAR reader** — archive manifests and entry extraction, written from the
  format description.
- **Tree indexer** — file, directory and language counts, sizes, largest files
  and notable manifests.
- **Parallel search** — literal and regular-expression search across a tree,
  split across a worker pool, reading files concurrently.
- **Chromium-family mapper** — the privacy subsystems present in a source
  tree, the files that implement them, and the GN build arguments that switch
  them on.
- **Browser identifier** — product, version, Chromium version and the feature
  markers compiled into an installed Chromium-family browser.
- **MCP server** — eight tools over JSON-RPC 2.0 on stdio, with a session
  cache and content-derived evidence identity.
- **Command line** — thirteen commands, `--json` and `--out` output.
- **Local console** — a single-page interface with the three typefaces and the
  server inlined into the shipped file.
- **35 tests**, including byte-level PE and ASAR fixtures.
