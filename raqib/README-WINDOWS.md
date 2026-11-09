# Raqib for Windows

A single file. Nothing to install.

`Raqib.exe` is a reverse-engineering workbench: it reads binaries, JavaScript
applications, ASAR archives, source maps and Chromium-family browser
installations, and it tells you what it found and what it could not prove.
It never runs the program it is looking at, and it never opens a socket.

**Node.js is not needed.** The executable carries its own JavaScript engine.
You do not need npm, Bun, Python, or a package manager of any kind.

---

## 1. Run it

Double-click `Raqib.exe`? No — it is a command line program. Open PowerShell
(or Command Prompt) in the folder the file is in and type:

```powershell
.\Raqib.exe --help
```

Or from anywhere, using the full path:

```powershell
C:\Tools\Raqib\Raqib.exe doctor
```

The program runs from any working directory. It does not need anything beside
it. You can copy `Raqib.exe` on its own to a USB stick and it will still work.

## 2. The first things worth trying

```powershell
# What is this machine, and what can Raqib do here?
.\Raqib.exe doctor

# Read a program that is already on the computer.
.\Raqib.exe analyze "C:\Windows\System32\notepad.exe"

# Name the browser that is installed.
.\Raqib.exe browser "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser"

# Look through a tree of files for a string.
.\Raqib.exe search "C:\Users\you\source" "API_KEY"

# Compare two builds of the same application.
.\Raqib.exe compare .\old-build .\new-build
```

## 3. Every command

| Command | What it does |
| --- | --- |
| `analyze <path>` | Read anything: ELF, PE, Mach-O, JavaScript, ASAR, a manifest, a browser |
| `elf <path>` | An ELF image: sections, segments, symbols, hardening |
| `pe <path>` | A Windows image: headers, imports, exports, an import hash |
| `macho <path>` | A Mach-O image: load commands, segments, symbols |
| `js <path>` | A JavaScript application: entry points, sources, packages |
| `asar <path>` | An ASAR archive: the manifest, and any file inside it |
| `strings <path>` | The strings a file carries |
| `search <path> <needle>` | Search a tree of files; `--workers n` for the parallel engine |
| `index <path>` | Count a tree: files, languages, bytes |
| `chromium <path>` | What a Chromium-family source tree is made of |
| `browser <path>` | Name the browser in an installation folder |
| `map <path>` | Resolve a position in a bundle back to its original source |
| `compare <a> <b>` | What changed between two analyses |
| `manifest <path>` | Read a `package.json` |
| `serve` | A local console in the browser; the server is on your machine only |
| `mcp` | The Model Context Protocol server, on standard input and output |
| `setup <agent>` | Register the MCP server with Claude, Codex, Cursor or Gemini |
| `doctor` | What this machine offers, and what Raqib will not do |
| `version`, `help` | The version, and the list of commands |

## 4. The parallel search engine

Raqib reads files on several threads at once when there is more than one core
to read them with. Ask for it by name when you want it, or let it decide:

```powershell
.\Raqib.exe search C:\code "needle" --workers 4
```

The summary tells you how the search was actually run:

```
200 match(es) in 216 file(s) — 1501 scanned in 217.6 ms using 2 worker thread(s)
```

## 5. The MCP server

`Raqib.exe mcp` speaks the Model Context Protocol over standard input and
output. It carries **11 tools**:

`inspect_binary`, `analyze_js_application`, `search_code`, `index_tree`,
`inspect_chromium_tree`, `identify_browser`, `read_asar`, `inspect_manifest`,
`resolve_source_map`, `compare_analyses`, `get_evidence`.

To let a local agent use it:

```powershell
.\Raqib.exe setup claude     # or: codex, cursor, gemini
```

This only writes a line into a configuration file on your own machine. It
downloads nothing, and it contacts nobody.

## 6. Checking the file

The archive carries the checksum of the executable. To check it yourself:

```powershell
Get-FileHash -LiteralPath .\Raqib.exe -Algorithm SHA256
```

It must match the line in `SHA256SUMS`.

## 7. What it will not do

- It does not execute the program it analyses.
- It does not open a network connection.
- It does not install anything, and it does not write to your system unless
  you ask it to (`setup` and `serve` are the only two that write).
- It does not repair, patch or decompile anything. It reports what is there.

## 8. If something goes wrong

| What you see | What it means |
| --- | --- |
| `SmartScreen` warns about an unknown publisher | The executable is not signed. It is built by an open source project on a GitHub Actions runner. |
| The antivirus quarantines it | A program that carries its own engine and writes a temporary file will look unusual to some scanners. The source of the whole build is public. |
| `raqib: no worker script beside the executable` | The executable is complete on its own; this message means a file was removed from a copy of it. Download it again. |

## 9. The same program, as a JavaScript file

The archive also carries `script/raqib.mjs` and `script/searchWorker.mjs` —
the very same program, to be run with Node.js 20.11 or newer:

```powershell
node .\script\raqib.mjs --help
```

The executable and the script are the same code. The executable is the script
with a JavaScript engine folded into it.

## 10. Where it came from

Raqib is an independent, offline re-implementation, written in TypeScript with
no runtime dependencies at all. `BUILD-INFO.txt` inside the archive says
exactly what was built, when, and how it was checked on a real Windows
machine.
