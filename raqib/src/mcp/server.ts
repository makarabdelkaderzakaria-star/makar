/**
 * Raqib's MCP server: JSON-RPC 2.0 over newline-delimited stdio.
 *
 * The whole server is a few hundred lines and has no dependencies, so an
 * agent can start it in milliseconds and it never reaches the network.
 */
import { createInterface } from 'node:readline';
import { stat } from 'node:fs/promises';
import { readFile } from 'node:fs/promises';
import { basename } from 'node:path';
import { inspectElf, parseElf } from '../core/elf.js';
import { inspectPe, parsePe } from '../core/pe.js';
import { analyzeJsApplication, jsApplicationEvidence } from '../core/js.js';
import { indexTree } from '../core/indexer.js';
import { searchTree } from '../core/search.js';
import { analyzeChromiumTree, chromiumTreeEvidence, identifyBrowser, browserIdentityEvidence } from '../core/chromium.js';
import { inspectStrings } from '../core/strings.js';
import { asarEvidence, readAsarFile, readAsarManifest } from '../core/asar.js';
import { walk } from '../core/util.js';
import { makeEvidence, type Evidence } from '../core/evidence.js';

export const SERVER_NAME = 'raqib';
export const SERVER_VERSION = '0.1.0';
const DEFAULT_PROTOCOL = '2025-06-18';
const KNOWN_PROTOCOLS = new Set(['2024-11-05', '2025-03-26', '2025-06-18']);

export interface JsonRpcMessage {
  jsonrpc?: string;
  id?: string | number | null;
  method?: string;
  params?: Record<string, unknown>;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
}

export interface ToolDefinition {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}

export const TOOLS: ToolDefinition[] = [
  {
    name: 'inspect_binary',
    description:
      'Inspect a native binary (ELF or PE) and return its structure: header, sections, ' +
      'imports, exports, build id, hardening flags and printable strings.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Absolute path to the binary.' },
        strings: { type: 'boolean', description: 'Also extract printable strings (default true).' },
        maxStrings: { type: 'number', description: 'Maximum number of strings to return (default 2000).' },
      },
      required: ['path'],
    },
  },
  {
    name: 'analyze_js_application',
    description:
      'Analyse a JavaScript, Electron or Node application directory: module graph, ' +
      'package manifest, Electron boundaries and the IPC channel inventory.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Absolute path to the application directory.' },
      },
      required: ['path'],
    },
  },
  {
    name: 'search_code',
    description:
      'Search the contents of a directory tree for a literal string or regular expression, ' +
      'returning file/line/column matches with surrounding context.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Absolute path to the tree to search.' },
        pattern: { type: 'string', description: 'Literal text or regular expression.' },
        regex: { type: 'boolean', description: 'Treat the pattern as a regular expression.' },
        caseSensitive: { type: 'boolean', description: 'Match case exactly (default false).' },
        maxResults: { type: 'number', description: 'Maximum number of matches (default 200).' },
        contextLines: { type: 'number', description: 'Lines of context around each match (default 0).' },
      },
      required: ['path', 'pattern'],
    },
  },
  {
    name: 'index_tree',
    description:
      'Inventory a directory tree: file and directory counts, size by language, largest files, ' +
      'and the manifests that usually matter.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Absolute path to the directory.' },
        maxDepth: { type: 'number', description: 'Maximum directory depth to descend (default 64).' },
      },
      required: ['path'],
    },
  },
  {
    name: 'inspect_chromium_tree',
    description:
      'Map a Chromium-family source tree (brave-core, chromium, or a fork): which privacy ' +
      'subsystems are present, which build arguments exist, and where each subsystem lives.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Absolute path to the source tree.' },
      },
      required: ['path'],
    },
  },
  {
    name: 'identify_browser',
    description:
      'Identify an installed Chromium-family browser from its own binaries: product, version, ' +
      'Chromium version and the feature markers compiled into it.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Absolute path to the browser installation directory.' },
      },
      required: ['path'],
    },
  },
  {
    name: 'read_asar',
    description:
      'Read an Electron .asar archive: its manifest, the files it contains, and optionally the ' +
      'contents of one entry.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Absolute path to the .asar archive.' },
        entry: { type: 'string', description: 'Path of an entry inside the archive to read.' },
      },
      required: ['path'],
    },
  },
  {
    name: 'get_evidence',
    description: 'Return a previously produced Evidence record by its id.',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string', description: 'The evidence id, e.g. "ev_1a2b3c4d5e6f7890".' },
      },
      required: ['id'],
    },
  },
];

export interface ToolResult {
  content: Array<{ type: 'text'; text: string }>;
  structuredContent?: Record<string, unknown>;
  isError?: boolean;
}

/** The MCP server session: holds the evidence cache and the negotiated protocol. */
export class RaqibMcpServer {
  private readonly evidence = new Map<string, Evidence>();
  private protocol = DEFAULT_PROTOCOL;
  private clientName = 'unknown';
  private clientVersion = 'unknown';

  get negotiatedProtocol(): string {
    return this.protocol;
  }

  /** Handle one JSON-RPC message. Returns null for notifications. */
  async handle(message: JsonRpcMessage): Promise<JsonRpcMessage | null> {
    const id = message.id;
    const method = message.method ?? '';

    if (id === undefined || id === null) {
      // Notification: acknowledged silently, per the specification.
      if (method === 'notifications/initialized') return null;
      return null;
    }

    try {
      const result = await this.dispatch(method, message.params ?? {});
      return { jsonrpc: '2.0', id, result };
    } catch (error) {
      const message_ = error instanceof Error ? error.message : String(error);
      return {
        jsonrpc: '2.0',
        id,
        error: { code: -32000, message: message_ },
      };
    }
  }

  private async dispatch(method: string, params: Record<string, unknown>): Promise<unknown> {
    switch (method) {
      case 'initialize': {
        const requested = typeof params.protocolVersion === 'string' ? params.protocolVersion : '';
        this.protocol = KNOWN_PROTOCOLS.has(requested) ? requested : DEFAULT_PROTOCOL;
        const clientInfo = (params.clientInfo ?? {}) as { name?: string; version?: string };
        this.clientName = clientInfo.name ?? 'unknown';
        this.clientVersion = clientInfo.version ?? 'unknown';
        return {
          protocolVersion: this.protocol,
          capabilities: { tools: { listChanged: false } },
          serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
          instructions:
            'Raqib inspects binaries, JavaScript applications, ASAR archives and Chromium-family ' +
            'source trees without executing the target. Every answer carries Evidence: facts, the ' +
            'locations they came from, and the questions the run could not answer.',
        };
      }
      case 'ping':
        return {};
      case 'tools/list':
        return { tools: TOOLS };
      case 'tools/call':
        return this.callTool(String(params.name ?? ''), (params.arguments ?? {}) as Record<string, unknown>);
      default:
        throw new Error(`unknown method: ${method}`);
    }
  }

  private async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    switch (name) {
      case 'inspect_binary':
        return this.inspectBinary(args);
      case 'analyze_js_application':
        return this.analyzeApplication(args);
      case 'search_code':
        return this.searchCode(args);
      case 'index_tree':
        return this.indexTree(args);
      case 'inspect_chromium_tree':
        return this.inspectChromiumTree(args);
      case 'identify_browser':
        return this.identifyBrowser(args);
      case 'read_asar':
        return this.readAsar(args);
      case 'get_evidence':
        return this.getEvidence(args);
      default:
        throw new Error(`unknown tool: ${name}`);
    }
  }

  private remember(evidence: Evidence): Evidence {
    this.evidence.set(evidence.id, evidence);
    if (this.evidence.size > 64) {
      const oldest = this.evidence.keys().next().value;
      if (oldest) this.evidence.delete(oldest);
    }
    return evidence;
  }

  private async inspectBinary(args: Record<string, unknown>): Promise<ToolResult> {
    const path = requireString(args, 'path');
    const buffer = await readFile(path);
    const isElf = buffer.length > 4 && buffer.readUInt32BE(0) === 0x7f454c46;
    const isPe = buffer.length > 0x40 && buffer[0] === 0x4d && buffer[1] === 0x5a;

    if (isElf) {
      const { evidence } = await inspectElf(path);
      this.remember(evidence);
      if (args.strings !== false) {
        const strings = await inspectStrings(path, { maxStrings: Number(args.maxStrings ?? 2000) });
        evidence.facts.push({ label: 'strings.total', value: String(strings.strings.length) });
        evidence.data = { ...(evidence.data ?? {}), strings: strings.strings };
      }
      return toToolResult(evidence);
    }
    if (isPe) {
      const { evidence } = await inspectPe(path);
      this.remember(evidence);
      return toToolResult(evidence);
    }
    throw new Error(`${path} is neither an ELF nor a PE image`);
  }

  private async analyzeApplication(args: Record<string, unknown>): Promise<ToolResult> {
    const path = requireString(args, 'path');
    const entries = await walk(path);
    const files = entries.filter((e) => !e.isDirectory).map((e) => ({ path: e.path, rel: e.rel, size: e.size }));
    const analysis = await analyzeJsApplication(path, files);
    const evidence = jsApplicationEvidence(analysis);
    this.remember(evidence);
    return toToolResult(evidence);
  }

  private async searchCode(args: Record<string, unknown>): Promise<ToolResult> {
    const path = requireString(args, 'path');
    const pattern = requireString(args, 'pattern');
    const result = await searchTree(path, {
      pattern,
      regex: Boolean(args.regex),
      caseSensitive: Boolean(args.caseSensitive),
      maxResults: Number(args.maxResults ?? 200),
      contextLines: Number(args.contextLines ?? 0),
    });
    const evidence = makeEvidence({
      kind: 'search',
      subject: path,
      summary:
        `${result.matches.length} match(es) for ${result.regex ? '/' + pattern + '/' : `"${pattern}"`} ` +
        `in ${result.filesScanned} file(s) across ${result.workers} worker(s) in ${result.elapsedMs.toFixed(0)} ms.`,
      facts: [
        { label: 'search.pattern', value: pattern },
        { label: 'search.regex', value: String(result.regex) },
        { label: 'search.matches', value: String(result.matches.length) },
        { label: 'search.files_scanned', value: String(result.filesScanned) },
        { label: 'search.files_with_matches', value: String(result.filesWithMatches) },
        { label: 'search.elapsed_ms', value: result.elapsedMs.toFixed(1) },
      ],
      locations: result.matches.slice(0, 200).map((m) => ({ file: m.file, line: m.line, column: m.column, note: m.text })),
      metrics: [
        { label: 'search.matches', value: result.matches.length },
        { label: 'search.elapsed_ms', value: result.elapsedMs },
      ],
      limitations: result.truncated
        ? ['The result set was truncated at the requested maximum; raise "maxResults" to see more.']
        : [],
      data: { matches: result.matches },
    });
    this.remember(evidence);
    return toToolResult(evidence);
  }

  private async indexTree(args: Record<string, unknown>): Promise<ToolResult> {
    const path = requireString(args, 'path');
    const index = await indexTree(path, { maxDepth: Number(args.maxDepth ?? 64) });
    const evidence = makeEvidence({
      kind: 'tree-index',
      subject: path,
      summary:
        `${index.fileCount} files and ${index.directoryCount} directories ` +
        `(${index.totalBytes} bytes); top languages: ` +
        `${index.languages.slice(0, 4).map((l) => `${l.language} (${l.files})`).join(', ') || 'none'}.`,
      facts: [
        { label: 'tree.files', value: String(index.fileCount) },
        { label: 'tree.directories', value: String(index.directoryCount) },
        { label: 'tree.bytes', value: String(index.totalBytes) },
        { label: 'tree.elapsed_ms', value: index.elapsedMs.toFixed(1) },
      ],
      metrics: [
        { label: 'tree.files', value: index.fileCount },
        { label: 'tree.bytes', value: index.totalBytes },
      ],
      limitations: [
        'Ignored directories (node_modules, .git, build output) are excluded from the counts.',
      ],
      data: index as unknown as Record<string, unknown>,
    });
    this.remember(evidence);
    return toToolResult(evidence);
  }

  private async inspectChromiumTree(args: Record<string, unknown>): Promise<ToolResult> {
    const path = requireString(args, 'path');
    const analysis = await analyzeChromiumTree(path);
    const evidence = chromiumTreeEvidence(analysis);
    this.remember(evidence);
    return toToolResult(evidence);
  }

  private async identifyBrowser(args: Record<string, unknown>): Promise<ToolResult> {
    const path = requireString(args, 'path');
    const identity = await identifyBrowser(path);
    const evidence = browserIdentityEvidence(identity);
    this.remember(evidence);
    return toToolResult(evidence);
  }

  private async readAsar(args: Record<string, unknown>): Promise<ToolResult> {
    const path = requireString(args, 'path');
    const entry = typeof args.entry === 'string' ? args.entry : null;

    if (!entry) {
      const { manifest, evidence } = await asarEvidence(path);
      this.remember(evidence);
      return toToolResult(evidence);
    }

    const manifest = await readAsarManifest(path);
    const contents = await readAsarFile(manifest, entry);
    if (!contents) {
      throw new Error(`entry not found or unpacked: ${entry}`);
    }
    const text = contents.toString('utf8');
    const evidence = makeEvidence({
      kind: 'asar-entry',
      subject: `${path}!${entry}`,
      summary: `Read ${entry} from the archive (${contents.length} bytes).`,
      facts: [
        { label: 'asar.entry', value: entry },
        { label: 'asar.entry_bytes', value: String(contents.length) },
      ],
      limitations: ['Binary entries are returned as latin1 text, so bytes above 0x7f are not faithful.'],
      data: { entry, bytes: contents.length, text: text.slice(0, 200000) },
    });
    this.remember(evidence);
    return toToolResult(evidence);
  }

  private async getEvidence(args: Record<string, unknown>): Promise<ToolResult> {
    const id = requireString(args, 'id');
    const evidence = this.evidence.get(id);
    if (!evidence) throw new Error(`no evidence with id ${id} in this session`);
    return toToolResult(evidence);
  }
}

function requireString(args: Record<string, unknown>, key: string): string {
  const value = args[key];
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`"${key}" is required and must be a non-empty string`);
  }
  return value;
}

function toToolResult(evidence: Evidence): ToolResult {
  return {
    content: [{ type: 'text', text: renderEvidenceText(evidence) }],
    structuredContent: { evidence_id: evidence.id, normalized_result: evidence },
  };
}

/** A compact, readable rendering of an Evidence record for the text channel. */
export function renderEvidenceText(evidence: Evidence): string {
  const lines: string[] = [];
  lines.push(`# ${evidence.kind} — ${evidence.subject}`);
  lines.push('');
  lines.push(evidence.summary);
  lines.push('');
  lines.push(`evidence_id: ${evidence.id}`);
  if (evidence.facts.length) {
    lines.push('');
    lines.push('## Facts');
    for (const fact of evidence.facts) {
      const source = fact.source ? `  (${fact.source.file}${fact.source.line ? `:${fact.source.line}` : ''})` : '';
      lines.push(`- ${fact.label}: ${fact.value}${source}`);
    }
  }
  if (evidence.locations.length) {
    lines.push('');
    lines.push('## Locations');
    for (const location of evidence.locations.slice(0, 100)) {
      const position = `${location.file}${location.line ? `:${location.line}` : ''}${location.column ? `:${location.column}` : ''}`;
      lines.push(`- ${position}${location.note ? ` — ${location.note}` : ''}`);
    }
  }
  if (evidence.limitations.length) {
    lines.push('');
    lines.push('## Not proven');
    for (const limitation of evidence.limitations) lines.push(`- ${limitation}`);
  }
  return lines.join('\n');
}

/** Run the MCP server on stdin/stdout until the input stream closes. */
export async function runMcpServer(): Promise<void> {
  const server = new RaqibMcpServer();
  const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });

  for await (const line of rl) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    let message: JsonRpcMessage;
    try {
      message = JSON.parse(trimmed) as JsonRpcMessage;
    } catch {
      process.stdout.write(`${JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'parse error' } })}\n`);
      continue;
    }
    const response = await server.handle(message);
    if (response) {
      process.stdout.write(`${JSON.stringify(response)}\n`);
    }
  }
}

/** Convenience for the CLI: describe a path without knowing what it is. */
export async function describePath(path: string): Promise<string> {
  const info = await stat(path);
  if (info.isDirectory()) return `directory with ${basename(path)}`;
  return `file with ${basename(path)}`;
}

export { parseElf, parsePe };
