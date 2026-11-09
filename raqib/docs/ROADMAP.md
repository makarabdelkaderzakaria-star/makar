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

## 0.2 — next

- **DWARF and PDB**: read the debug information so a stripped binary can
  still be named.
- **Mach-O**: the third executable format, for macOS targets.
- **Import hashing**: the same import-hash fingerprints that IDA and pefile
  publish, so a binary can be matched against a known family.
- **Source maps**: resolve a bundle's `sourceMappingURL` back to the original
  TypeScript, which is the single biggest legibility win for a minified
  Electron app.
- **`.d.ts` and package exports**: resolve a modern package's entry points
  the way Node does, instead of guessing from `main`.
- **Diff two analyses**: compare two Evidence records by id and report what
  changed between two builds of the same application.

## 0.3 — later

- **A `.pak` reader** for Chromium resource bundles.
- **Extension manifests**: Chrome/Brave extension analysis.
- **A signed evidence bundle**: hash the whole session so an answer can be
  shown to have been produced by a given binary.
- **A plugin interface** — but only if it does not cost the 52 ms start.

## Deliberately not planned

- **Executing the target.** Raqib stays static.
- **A network client.** No downloads, no update checks, no telemetry.
- **Bundled decompilers.** Ghidra, IDA and Hopper are better at this and
  already exist; Raqib's job is to find and read what they are pointed at.
- **A hosted service.** The tool runs on your machine, on your files.
