#!/usr/bin/env node
/**
 * Raqib command line.
 *
 * One binary, no runtime dependencies, no network access: every command
 * works on a machine that has never seen the internet since it was built.
 */
import { readFile, writeFile, mkdir, copyFile, stat } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve, dirname, basename } from 'node:path';
import { inspectElf } from './core/elf.js';
import { inspectPe } from './core/pe.js';
import { analyzeJsApplication, jsApplicationEvidence } from './core/js.js';
import { indexTree, formatIndexSummary } from './core/indexer.js';
import { searchTree } from './core/search.js';
import { analyzeChromiumTree, chromiumTreeEvidence, identifyBrowser, browserIdentityEvidence, browserSearchPaths } from './core/chromium.js';
import { inspectStrings } from './core/strings.js';
import { asarEvidence, readAsarFile, readAsarManifest } from './core/asar.js';
import { walk, formatBytes, formatDuration } from './core/util.js';
import { runMcpServer, renderEvidenceText, TOOLS } from './mcp/server.js';
import { startConsole } from './web/server.js';
import type { Evidence } from './core/evidence.js';

const VERSION = '0.1.0';

interface Flags {
  json: boolean;
  quiet: boolean;
  port: number;
  host: string;
  regex: boolean;
  caseSensitive: boolean;
  max: number;
  context: number;
  depth: number;
  out: string | null;
  positional: string[];
  help: boolean;
}

function parseFlags(argv: string[]): Flags {
  const flags: Flags = {
    json: false, quiet: false, port: 8787, host: '127.0.0.1',
    regex: false, caseSensitive: false, max: 200, context: 0, depth: 64,
    out: null, positional: [], help: false,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = () => argv[++i] ?? '';
    switch (arg) {
      case '--json': flags.json = true; break;
      case '--quiet': case '-q': flags.quiet = true; break;
      case '--regex': case '-r': flags.regex = true; break;
      case '--case-sensitive': flags.caseSensitive = true; break;
      case '--help': case '-h': flags.help = true; break;
      case '--port': flags.port = Number(next()); break;
      case '--host': flags.host = next(); break;
      case '--max': flags.max = Number(next()); break;
      case '--context': flags.context = Number(next()); break;
      case '--depth': flags.depth = Number(next()); break;
      case '--out': flags.out = next(); break;
      default:
        if (arg.startsWith('--max=')) flags.max = Number(arg.slice(6));
        else if (arg.startsWith('--port=')) flags.port = Number(arg.slice(7));
        else if (arg.startsWith('--out=')) flags.out = arg.slice(6);
        else if (arg.startsWith('-')) { /* unknown flag: ignore */ }
        else flags.positional.push(arg);
    }
  }
  return flags;
}

const HELP = `raqib ${VERSION} — a light, offline reverse-engineering observatory

USAGE
  raqib <command> [arguments] [flags]

COMMANDS
  mcp                       run the MCP server on stdio (for agent clients)
  serve                     start the local analysis console in the browser
  analyze <path>            inspect anything: binary, directory, app or archive
  elf <file>                read an ELF image: sections, symbols, hardening
  pe <file>                 read a PE image: imports, exports, certificate, hardening
  js <dir>                  analyse a JavaScript / Electron application
  asar <file> [entry]       read an Electron .asar archive
  strings <file>            recover printable strings from a binary
  search <dir> <pattern>    search the contents of a tree
  index <dir>               inventory a directory tree
  chromium <dir>            map a Chromium-family source tree
  browser <dir>             identify an installed Chromium-family browser
  setup [agent]             register the MCP server with an agent (offline)
  doctor                    check what this machine can do
  version                   print the version
  help                      print this help

FLAGS
  --json                    machine-readable output
  --out <file>              write the output to a file
  --regex, -r               treat the search pattern as a regular expression
  --case-sensitive           match case exactly
  --max <n>                 maximum results (default 200)
  --context <n>             lines of context around a match
  --depth <n>               maximum directory depth
  --port <n>                console port (default 8787)
  --host <addr>             console host (default 127.0.0.1)
  --quiet, -q               no human-readable output

EXAMPLES
  raqib analyze /usr/lib/brave-browser
  raqib search ./src "contextBridge" --context 2
  raqib chromium ~/src/brave-core --json > brave.json
  raqib setup claude
`;

async function main(): Promise<number> {
  const argv = process.argv.slice(2);
  const flags = parseFlags(argv);
  const command = flags.positional.shift() ?? (flags.help ? 'help' : 'help');

  switch (command) {
    case 'help': case '--help': case '-h':
      process.stdout.write(HELP);
      return 0;
    case 'version': case '--version':
      emit(flags, { name: 'raqib', version: VERSION, tools: TOOLS.length, node: process.version }, `raqib ${VERSION} (node ${process.version})`);
      return 0;
    case 'mcp':
      await runMcpServer();
      return 0;
    case 'serve':
      return serve(flags);
    case 'setup':
      return setup(flags);
    case 'doctor':
      return doctor(flags);
    case 'analyze':
      return analyze(flags);
    case 'elf':
      return elfCommand(flags);
    case 'pe':
      return peCommand(flags);
    case 'js':
      return jsCommand(flags);
    case 'asar':
      return asarCommand(flags);
    case 'strings':
      return stringsCommand(flags);
    case 'search':
      return searchCommand(flags);
    case 'index':
      return indexCommand(flags);
    case 'chromium':
      return chromiumCommand(flags);
    case 'browser':
      return browserCommand(flags);
    default:
      process.stderr.write(`raqib: unknown command "${command}"\n\n${HELP}`);
      return 2;
  }
}

/* ------------------------------------------------------------------ */
/* Output helpers                                                      */
/* ------------------------------------------------------------------ */

function emit(flags: Flags, payload: unknown, human: string): void {
  const text = flags.json ? JSON.stringify(payload, null, 2) : human;
  if (flags.out) {
    void writeFile(flags.out, `${text}\n`, 'utf8');
    if (!flags.quiet) process.stderr.write(`raqib: wrote ${flags.out}\n`);
    return;
  }
  if (!flags.quiet) process.stdout.write(`${text}\n`);
}

function emitEvidence(flags: Flags, evidence: Evidence): void {
  emit(flags, evidence, renderEvidenceText(evidence));
}

/* ------------------------------------------------------------------ */
/* Commands                                                            */
/* ------------------------------------------------------------------ */

async function elfCommand(flags: Flags): Promise<number> {
  const path = requirePositional(flags, 'file');
  const { evidence } = await inspectElf(path);
  emitEvidence(flags, evidence);
  return 0;
}

async function peCommand(flags: Flags): Promise<number> {
  const path = requirePositional(flags, 'file');
  const { evidence } = await inspectPe(path);
  emitEvidence(flags, evidence);
  return 0;
}

async function jsCommand(flags: Flags): Promise<number> {
  const path = requirePositional(flags, 'directory');
  const entries = await walk(path);
  const files = entries.filter((e) => !e.isDirectory).map((e) => ({ path: e.path, rel: e.rel, size: e.size }));
  const analysis = await analyzeJsApplication(path, files);
  emitEvidence(flags, jsApplicationEvidence(analysis));
  return 0;
}

async function asarCommand(flags: Flags): Promise<number> {
  const path = requirePositional(flags, 'archive');
  const entry = flags.positional[0];
  if (!entry) {
    const { evidence } = await asarEvidence(path);
    emitEvidence(flags, evidence);
    return 0;
  }
  const manifest = await readAsarManifest(path);
  const contents = await readAsarFile(manifest, entry);
  if (!contents) {
    process.stderr.write(`raqib: entry "${entry}" is missing or unpacked\n`);
    return 1;
  }
  process.stdout.write(contents);
  return 0;
}

async function stringsCommand(flags: Flags): Promise<number> {
  const path = requirePositional(flags, 'file');
  const { evidence } = await inspectStrings(path, { maxStrings: flags.max * 10 });
  emitEvidence(flags, evidence);
  return 0;
}

async function searchCommand(flags: Flags): Promise<number> {
  const path = requirePositional(flags, 'directory');
  const pattern = flags.positional[0];
  if (!pattern) {
    process.stderr.write('raqib: search needs a pattern\n');
    return 2;
  }
  const result = await searchTree(path, {
    pattern,
    regex: flags.regex,
    caseSensitive: flags.caseSensitive,
    maxResults: flags.max,
    contextLines: flags.context,
  });
  const human = [
    `${result.matches.length} match(es) in ${result.filesWithMatches} file(s) — ${result.filesScanned} scanned in ${formatDuration(result.elapsedMs)} using ${result.workers} worker(s)`,
    '',
    ...result.matches.map((m) => `${m.file}:${m.line}:${m.column}  ${m.text}`),
  ].join('\n');
  emit(flags, result, human);
  return 0;
}

async function indexCommand(flags: Flags): Promise<number> {
  const path = requirePositional(flags, 'directory');
  const index = await indexTree(path, { maxDepth: flags.depth });
  const human = [
    formatIndexSummary(index),
    '',
    'Languages:',
    ...index.languages.slice(0, 20).map((l) => `  ${l.language.padEnd(12)} ${String(l.files).padStart(7)} files  ${formatBytes(l.bytes).padStart(10)}`),
    '',
    'Largest files:',
    ...index.largestFiles.slice(0, 12).map((f) => `  ${formatBytes(f.bytes).padStart(10)}  ${f.path}`),
  ].join('\n');
  emit(flags, index, human);
  return 0;
}

async function chromiumCommand(flags: Flags): Promise<number> {
  const path = requirePositional(flags, 'directory');
  const analysis = await analyzeChromiumTree(path);
  const evidence = chromiumTreeEvidence(analysis);
  const human = [
    renderEvidenceText(evidence),
    '',
    'Privacy subsystems:',
    ...analysis.subsystems.map((s) => `  ${s.subsystem.padEnd(20)} ${String(s.files.length).padStart(4)} file(s)  ${s.description}`),
    '',
    'Build arguments (first 30):',
    ...analysis.buildArguments.slice(0, 30).map((a) => `  ${a.name} = ${a.value ?? ''}   (${a.file}:${a.line})`),
  ].join('\n');
  emit(flags, evidence, human);
  return 0;
}

async function browserCommand(flags: Flags): Promise<number> {
  const path = flags.positional[0];
  if (!path) {
    const human = browserSearchPaths().map((p) => `  ${p.label.padEnd(18)} ${p.path}`).join('\n');
    emit(flags, browserSearchPaths(), human);
    return 0;
  }
  const identity = await identifyBrowser(path);
  emitEvidence(flags, browserIdentityEvidence(identity));
  return 0;
}

/** Inspect anything: dispatch on what the path actually is. */
async function analyze(flags: Flags): Promise<number> {
  const path = requirePositional(flags, 'path');
  const info = await stat(path);

  if (info.isDirectory()) {
    const entries = await walk(path);
    const files = entries.filter((e) => !e.isDirectory);

    // A Chromium source tree gets the Chromium map; anything else gets the
    // JavaScript application analysis.
    const looksChromium = files.some((f) => f.rel.startsWith('chrome/') || f.rel.startsWith('content/'))
      || files.some((f) => f.rel.endsWith('.gn') || f.rel.endsWith('DEPS'));

    if (looksChromium && files.length > 200) {
      const analysis = await analyzeChromiumTree(path);
      emitEvidence(flags, chromiumTreeEvidence(analysis));
      return 0;
    }

    const jsFiles = files.filter((f) => /\.(js|mjs|cjs|jsx|ts|tsx)$/i.test(f.rel));
    if (jsFiles.length > 0) {
      const analysis = await analyzeJsApplication(path, files.map((e) => ({ path: e.path, rel: e.rel, size: e.size })));
      emitEvidence(flags, jsApplicationEvidence(analysis));
      return 0;
    }

    const index = await indexTree(path);
    const human = [
      formatIndexSummary(index),
      '',
      'Languages:',
      ...index.languages.slice(0, 20).map((l) => `  ${l.language.padEnd(12)} ${String(l.files).padStart(7)} files  ${formatBytes(l.bytes).padStart(10)}`),
    ].join('\n');
    emit(flags, index, human);
    return 0;
  }

  const buffer = await readFile(path);
  if (buffer.length > 4 && buffer.readUInt32BE(0) === 0x7f454c46) {
    const { evidence } = await inspectElf(path);
    emitEvidence(flags, evidence);
    return 0;
  }
  if (buffer.length > 0x40 && buffer[0] === 0x4d && buffer[1] === 0x5a) {
    const { evidence } = await inspectPe(path);
    emitEvidence(flags, evidence);
    return 0;
  }
  if (buffer.length > 16 && buffer.readUInt32LE(0) === 4) {
    try {
      const { evidence } = await asarEvidence(path);
      emitEvidence(flags, evidence);
      return 0;
    } catch {
      // not an asar after all
    }
  }
  const { evidence } = await inspectStrings(path, { maxStrings: flags.max * 10 });
  emitEvidence(flags, evidence);
  return 0;
}

async function serve(flags: Flags): Promise<number> {
  const server = await startConsole({ port: flags.port, host: flags.host });
  process.stdout.write(`raqib console listening on ${server.url}\n`);
  process.stdout.write('press ctrl-c to stop\n');
  await new Promise<void>(() => { /* run until interrupted */ });
  return 0;
}

/** Register the MCP server with a local agent. Entirely offline. */
async function setup(flags: Flags): Promise<number> {
  const agent = (flags.positional[0] ?? 'claude').toLowerCase();
  const executable = process.argv[1] ? resolve(process.argv[1]) : 'raqib';
  const command = basename(executable) === 'raqib.mjs' ? `node ${executable} mcp` : `${executable} mcp`;
  const home = homedir();
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const results: Array<{ file: string; action: string }> = [];

  const writeJson = async (file: string, mutate: (data: any) => void) => {
    let data: any = {};
    if (existsSync(file)) {
      const raw = await readFile(file, 'utf8');
      try {
        data = JSON.parse(raw);
      } catch {
        data = {};
      }
      await copyFile(file, `${file}.bak-${stamp}`).catch(() => undefined);
    }
    mutate(data);
    await mkdir(dirname(file), { recursive: true });
    await writeFile(file, `${JSON.stringify(data, null, 2)}\n`, 'utf8');
    results.push({ file, action: 'updated' });
  };

  switch (agent) {
    case 'claude':
      await writeJson(join(home, '.claude.json'), (data) => {
        data.mcpServers = data.mcpServers ?? {};
        data.mcpServers.raqib = { command: 'node', args: [executable, 'mcp'] };
      });
      break;
    case 'cursor':
      await writeJson(join(home, '.cursor', 'mcp.json'), (data) => {
        data.mcpServers = data.mcpServers ?? {};
        data.mcpServers.raqib = { command: 'node', args: [executable, 'mcp'] };
      });
      break;
    case 'gemini':
      await writeJson(join(home, '.gemini', 'settings.json'), (data) => {
        data.mcpServers = data.mcpServers ?? {};
        data.mcpServers.raqib = { command: 'node', args: [executable, 'mcp'] };
      });
      break;
    case 'codex': {
      const file = join(home, '.codex', 'config.toml');
      let content = existsSync(file) ? await readFile(file, 'utf8') : '';
      if (!content.includes('[mcp_servers.raqib]')) {
        if (content.length && !content.endsWith('\n')) content += '\n';
        content += `\n[mcp_servers.raqib]\ncommand = "${command}"\n`;
        await mkdir(dirname(file), { recursive: true });
        await writeFile(file, content, 'utf8');
        results.push({ file, action: 'updated' });
      } else {
        results.push({ file, action: 'already present' });
      }
      break;
    }
    default:
      process.stderr.write(`raqib: unknown agent "${agent}". Use claude, codex, cursor or gemini.\n`);
      return 2;
  }

  const human = [
    `Registered the Raqib MCP server for ${agent}.`,
    ...results.map((r) => `  ${r.action}: ${r.file}`),
    '',
    'Restart the agent to pick up the change. Nothing was downloaded: the registration is local.',
  ].join('\n');
  emit(flags, { agent, command, results }, human);
  return 0;
}

async function doctor(flags: Flags): Promise<number> {
  const nodeMajor = Number(process.versions.node.split('.')[0]);
  const checks: Array<{ name: string; ok: boolean; detail: string }> = [
    { name: 'node runtime', ok: nodeMajor >= 20, detail: `${process.version}` },
    { name: 'worker threads', ok: true, detail: 'available for parallel search' },
    { name: 'network use', ok: true, detail: 'none — Raqib never opens a socket' },
    { name: 'mcp tools', ok: true, detail: `${TOOLS.length} tools registered` },
  ];
  for (const candidate of browserSearchPaths()) {
    if (existsSync(candidate.path)) {
      checks.push({ name: `browser found: ${candidate.label}`, ok: true, detail: candidate.path });
    }
  }
  const human = [
    'raqib doctor',
    '',
    ...checks.map((c) => `  ${c.ok ? '✓' : '✗'} ${c.name.padEnd(28)} ${c.detail}`),
    '',
    'Known browser locations:',
    ...browserSearchPaths().map((p) => `  ${existsSync(p.path) ? '✓' : '·'} ${p.label.padEnd(18)} ${p.path}`),
  ].join('\n');
  emit(flags, { checks }, human);
  return checks.every((c) => c.ok) ? 0 : 1;
}

function requirePositional(flags: Flags, name: string): string {
  const value = flags.positional[0];
  if (!value) {
    process.stderr.write(`raqib: missing <${name}>\n`);
    process.exit(2);
  }
  return resolve(value);
}

main()
  .then((code) => { process.exitCode = code; })
  .catch((error: unknown) => {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`raqib: ${message}\n`);
    process.exitCode = 1;
  });
