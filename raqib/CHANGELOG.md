# Changelog

All notable changes to Raqib are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
