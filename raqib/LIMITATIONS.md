# Limitations

Everything Raqib cannot do, in one place. Each entry says what is missing and
what the tool does instead.

## It never executes the target

Raqib is static analysis only. It cannot tell you what an app *does* at
runtime, only what its bytes and its source say. Behaviour that is decided at
runtime — a feature flag read from a server, a value computed from a
timestamp, an A/B test — is invisible to it.

## It reads files; it does not understand programs

Finding `ipcMain.handle('feature:toggle')` proves the channel exists and where
it is declared. It does not prove the handler is correct, that the channel is
reachable, or that the renderer calls it. Raqib reports the **unmatched**
channels precisely because it cannot decide this on its own.

## Native analysis is shallow on purpose

- No disassembly, no decompilation, no control-flow reconstruction.
- No cross-references between functions.
- Stripped binaries expose only their dynamic symbols; internal names cannot
  be recovered.
- Debug information (DWARF, PDB) is not parsed yet.

For deep native work, use Ghidra, IDA or Hopper — and point Raqib at the
result.

## Formats it does not read

.NET assemblies, WASM, EVM bytecode, DEX, APK, PyInstaller, Deno compile
output, SQLite, firmware images, crash dumps, HAR/SAZ captures, PDF, and
images are all out of scope. Strings can still be recovered from any of them
with `raqib strings`.

Mach-O is read for its structure, but not deeply: there is no disassembly, no
Objective-C class metadata, and no Swift type reflection.

## The Chromium map is name-driven

`inspect_chromium_tree` finds subsystems by matching file names and
confirming by content. A fork that renames `fingerprinting` to something else
will not be found. The build-argument extraction reads the first 400 GN files
and stops there. Neither is a proof of absence.

## Installed-browser detection reads strings

`identify_browser` finds the product and version from the version markers
inside the executable and the feature list from the strings the build
compiled in. A feature that was compiled out leaves no marker, and a
feature that is present but disabled at runtime looks identical to one that is
enabled. `none detected` means *no marker was found*, not *the feature is
absent*.

## A manifest is a claim

`package.json` records what somebody intended to build. The dependency
versions in it are the versions that were *asked for*, not the versions that
are installed or vendored, and the entry point it names may not be the file
the application actually loads.

## Source maps are read, not trusted

The map is a claim made by the build, not a proof. A map can name files that
do not exist, or map positions wrongly. Raqib reports the map's own claims
and marks a resolution as *approximate* when it had to fall back to the
nearest preceding mapping.

## The JavaScript scanner is a lexer, not a parser

It masks strings, comments, template literals and regular-expression
literals before matching, which removes the usual false positives. It does not
build an AST, so it cannot resolve re-exports, aliased imports, or dynamic
`import()` targets that are computed at runtime. Files above 12 MiB are not
scanned.

## Search limits

- Literal search is exact; there is no fuzzy matching.
- Regular expressions are evaluated per file with JavaScript semantics.
- Binary files (a NUL byte in the first 8 KiB) are skipped.
- Files above 24 MiB are skipped.
- The default cap is 200 results; the answer says when it truncated.
- Case-insensitive matching lowercases the whole file, which costs memory on
  very large files.

## The console is local-only

It binds to `127.0.0.1` by default and serves paths from the machine it runs
on. Anyone who can reach the port can read the files that account can read.
Do not expose it to a network you do not control.

## What it does not do at all

- No network access, ever: not for setup, not for assets, not for updates.
- No telemetry, no crash reporting, no analytics.
- No execution of the target, no sandboxing, no privileges.
- No writes to the target tree. Raqib only ever reads it.
