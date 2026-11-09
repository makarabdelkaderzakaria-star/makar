# Raqib 0.2.0 for Windows

A single executable. No Node.js, no Bun, no npm, no dependencies.

**`Raqib.exe`** is 83,417,344 bytes and carries its own JavaScript engine.
Copy it anywhere and run it.

```
SHA256  26cee8edf5ef4c0d00b074580872889fa58ff1ffdd25742d5cb2ef32e11a6b06
```

---

## What was done

1. **The technique.** Node's own Single Executable Application: the program is
   bundled into one CommonJS file, that file is turned into a blob, and the
   blob is injected into a copy of the official Windows build of Node 22.23.4
   with `postject`. The result is one file that needs nothing installed.

   Bun was considered and rejected: it would have meant rewriting the worker
   resolution (`import.meta.url` does not survive a Bun standalone build), and
   it would have changed the behaviour of the analysis engine for no gain.
   Node's SEA leaves the program exactly as it was.

2. **The worker is inside.** The search worker used to be a file sitting
   beside the script. Inside an executable there is no file beside anything,
   so the worker's source is embedded in the bundle and written out to a
   temporary file the first time a worker is needed. The search engine itself
   was not changed.

3. **The build is reproducible.** Two things used to make every build
   different: the base runtime was whatever Node happened to be on the
   machine, and the SEA blob carried the absolute path of the bundle. Now the
   base runtime is always `node-win-x64@22.23.4` from the npm registry, the
   blob names the bundle relatively, and a `.gitattributes` makes every text
   file check out with the same line endings. The same source gives byte for
   byte the same executable on a laptop and on a build machine.

   That is what makes the checksum below mean something: the file that was
   tested on the Windows runner is the file that was published, down to the
   last byte.

## How it was checked

On a real Windows x64 machine (`windows-latest`), with **Node.js renamed out of
the way** and taken off the `PATH`, and with the executable copied into a
folder that held nothing else:

| # | Check | Result |
| --- | --- | --- |
| 0 | neither node nor bun is reachable | PASS |
| 1 | `--help` lists every command | PASS |
| 2 | `doctor` reports the machine | PASS |
| 3 | `analyze notepad.exe` | PASS |
| 4 | the PE report names its imports | PASS |
| 5 | identify the installed browser (a real Brave 1.101.38) | PASS |
| 6 | search a tree of 1500 files | PASS |
| 6 | the search used the worker threads | PASS — 2 worker threads |
| 7 | compare old-build with new-build | PASS |
| 8 | map a bundle back to its source | PASS |
| 9 | the map lists the original files | PASS |
| 10 | read an asar archive | PASS |
| 11 | read a package manifest | PASS |
| 12 | MCP lists all 11 tools | PASS |
| 13 | MCP answered a tool call | PASS |
| 14 | runs from an unrelated working directory | PASS |
| 15 | search a path with spaces and Arabic characters | PASS |
| 16 | analyse a file with an Arabic name | PASS |
| 17 | runs with nothing beside it | PASS |

**19 of 19.** The raw result is `results.json`, inside the archive.

The search really ran on the worker threads, not on the main thread:

```
200 match(es) in 216 file(s) — 1501 scanned in 280.7 ms using 2 worker thread(s)
```

## Where to get it

| What | Where |
| --- | --- |
| The archive (EXE + documentation + checksum + the script) | `Raqib-0.2.0-windows-x64.zip` |
| The executable on its own | `Raqib.exe` |
| The draft release on GitHub | tag `raqib-0.2.0-windows` |
| The source | the `raqib/` directory of this repository |

## The files

```
Raqib-0.2.0-windows-x64.zip
├── Raqib.exe                 the standalone executable
├── README-WINDOWS.md         how to use it
├── BUILD-INFO.txt            what it is, and how it was checked
├── SHA256SUMS                the checksum of the executable
├── results.json              the 19 checks, as they came back
└── script/
    ├── raqib.mjs             the same program, for Node.js 20.11 or newer
    └── searchWorker.mjs
```

The JavaScript copy is kept on purpose: the executable is the script with a
JavaScript engine folded into it, and both are the same program.

## Building it yourself

```bash
npm ci
npm run build:exe            # dist/Raqib.exe
npm run package:windows      # dist/Raqib-<version>-windows-x64.zip
```

`scripts/build-sea.mjs` downloads the Windows runtime from the npm registry if
it is not already in `dist/`. `scripts/build-info.mjs` writes the sheet that
says what was built, reading it from the files that are actually there.
