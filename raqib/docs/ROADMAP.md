# Roadmap

## 0.1 — shipped

- ELF and PE readers written from the specifications, no external tools.
- A JavaScript lexer that masks strings, comments, template literals and
  regex literals before matching.
- ASAR reading, including entry extraction.
- Tree indexing and parallel content search with a worker pool.
- A Chromium-family tree mapper (subsystems, GN arguments) and an installed
  browser identifier.
- An MCP server with eight tools, an evidence model with content-derived
  identity, a CLI, and a local console with the interface and fonts inlined.
- 35 tests, including a byte-level PE fixture and a byte-level ASAR fixture.

## 0.2 — shipped

- **Source maps**: a version-3 reader with a VLQ decoder, mapping positions
  in both directions, and listing the original files a bundle was built from.
- **Mach-O**: thin and universal binaries, load commands, dynamic libraries,
  sections, UUID, entry point and symbols.
- **Import hashing**: the classic PE import hash, so a binary can be matched
  against a known family by its imports alone.
- **Diff two analyses**: compare two Evidence records and report what
  changed — facts, locations and gaps.
- **Manifest reader**: a `package.json` read as structure, not as text.

## 0.3 — next

- **DWARF and PDB**: read the debug information so a stripped binary can
  still be named.
- **`.d.ts` and package exports**: resolve a modern package's entry points
  the way Node does, instead of guessing from `main`.
- **A `.pak` reader** for Chromium resource bundles.
- **Extension manifests**: Chrome/Brave extension analysis.

## 0.4 — later

- **A signed evidence bundle**: hash the whole session so an answer can be
  shown to have been produced by a given binary.
- **A plugin interface** — but only if it does not cost the 52 ms start.

## Deliberately not planned

- **Executing the target.** Raqib stays static.
- **A network client.** No downloads, no update checks, no telemetry.
- **Bundled decompilers.** Ghidra, IDA and Hopper are better at this and
  already exist; Raqib's job is to find and read what they are pointed at.
- **A hosted service.** The tool runs on your machine, on your files.
