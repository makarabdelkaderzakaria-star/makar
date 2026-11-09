# Raqib 0.2.0 — release note

**Raqib** is a light, offline reverse-engineering observatory: an MCP server, a
command line and a local console in a single 247 KB file with **zero runtime
dependencies** and no network access of any kind.

This release adds four capabilities, each of them something you need when you
are holding an unfamiliar binary or bundle and want to know what it is.

---

## What is new in 0.2.0

### Source maps — `raqib map ./dist/bundle.js`

A version-3 reader with a base64 VLQ decoder. It lists the original files a
bundle was built from, and maps positions in both directions:

```
raqib map ./dist/bundle.js --line 10 --column 20
  ->  ../src/main.ts:2:19

raqib map ./dist/bundle.js --source ../src/app.ts --line 5
  ->  dist/bundle.js:4:55
```

A position on a line that carries no mapping falls back to the nearest
preceding mapping and is marked *approximate*, rather than reporting nothing.

### Mach-O — `raqib macho /Applications/Safari.app`

Thin and universal binaries: header, load commands, segments and sections,
dynamic libraries, rpaths, UUID, entry point, symbol table, code signature.

### Manifests — `raqib manifest ./app/package.json`

A `package.json` read as structure rather than as text: name, version, entry
point, runtime and development dependencies, scripts, binaries, the engines it
demands, and the Electron version it was built against — wherever that version
was declared (electron-builder, electron-forge, or a plain script).

### Build diffing — `raqib compare ./old-build ./new-build`

```
0 fact(s) added, 0 removed, 5 changed; 0 location(s) added, 0 removed; 0 new gap(s), 0 closed.

  ~ manifest.version: 1.0.0  ->  1.1.0
  ~ app.source_bytes: 60  ->  90
  ~ ipc.handled_channels: 2  ->  3
```

Facts added, removed and changed; locations moved; gaps opened and closed.

---

## One dispatcher

`core/analyze.ts` is the only place that decides what a path is and how it
should be read. The MCP server (11 tools), the command line (19 commands) and
the local console all call it — so a new format is supported everywhere at
once, and there is exactly one definition of what `auto` means.

---

## Two bugs found while testing, and fixed

- A positional argument was read but never **consumed**: `compare left right`
  compared `left` with itself, and `asar file entry` ignored the entry.
- The source map VLQ decoder reported the number of *values* it read instead
  of the number of *characters*, which truncated every multi-field segment.

Both now have regression tests.

---

## Measured, on the same machine

| | REA 6.8.0 | Raqib 0.2.0 |
|---|---|---|
| install | 139 MB, 161 packages, 10.0 s | 0 dependencies |
| shipped | — | 247 KB, one file |
| startup | 1 034 ms | 51 ms |
| one Electron app | 8 253 ms, 27.2 MB | 68 ms, 3.2 KB |

Raqib's own benchmark (2 000-file / 44 MB fixture): cold start 51 ms, ELF
analysis 54 ms, index 152 ms, search 190 ms, JS application analysis 70 ms.

---

## Offline, and how it stays that way

- No telemetry, no update checks, no sockets. `raqib doctor` says so out loud.
- The three typefaces are embedded in the shipped file as base64; the console
  makes zero network requests.
- Nothing is fetched at setup time or at run time. `npm ci` installs dev
  dependencies only; the shipped file needs nothing but Node ≥ 20.11.

---

## Download

| | |
|---|---|
| Release bundle (linux x64) | https://drive.google.com/file/d/1tJ2HRimbSw5EaXFDIPG0b7SS9x9rEUCJ/view |
| Full source | https://drive.google.com/file/d/1fP6O91wP-_lvqrel5la7mBAn70TCqRcB/view |
| Folder | https://drive.google.com/drive/folders/1TijuzghilDd7xOTY0Zw_rOphb_Lo_BE_ |

Both files are readable by anyone with the link.

```bash
tar -xzf raqib-0.2.0-linux-x64.tar.gz
cd raqib-0.2.0-linux-x64
sha256sum -c SHA256SUMS
node raqib.mjs --help
```

The release bundle is self-contained: `raqib.mjs`, the search worker, the
documentation, `BUILD-INFO.txt` and `SHA256SUMS`. Nothing to install.

---

## SHA-256

```
ebda89b53da5b3d17035dd4970ab5e181af9a8af6e9e3ab05be0a62325c89d14  raqib-0.2.0-linux-x64.tar.gz
4d9aa178b973ad16355b4fadbdd660b599b60c630899857374cd487247bdc325  raqib-0.2.0-source.tar.gz
```

63 tests pass; `tsc --noEmit` is clean.
