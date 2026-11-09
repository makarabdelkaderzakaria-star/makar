/**
 * A JavaScript / TypeScript source scanner.
 *
 * It is a real lexer, not a regex sweep: strings, template literals, comments
 * and regular-expression literals are masked out before any pattern is
 * matched, so `// import 'x'` inside a comment and `const s = "require('y')"`
 * inside a string are never mistaken for dependencies.
 */
import { readFile } from 'node:fs/promises';
import { makeEvidence, type Evidence, type Fact } from './evidence.js';

export interface JsHit {
  /** What was found, e.g. "import", "ipc.handle". */
  kind: string;
  /** The interesting value, e.g. the module specifier or channel name. */
  value: string;
  line: number;
  column: number;
  /** The source line, trimmed. */
  text: string;
}

export interface JsScan {
  imports: JsHit[];
  exports: JsHit[];
  requires: JsHit[];
  /** Electron / Node API usage with the file position where it appears. */
  apis: JsHit[];
  /** IPC channels, keyed by direction. */
  channels: {
    handle: string[];
    on: string[];
    invoke: string[];
    send: string[];
    expose: string[];
  };
  /** webPreferences keys seen in the file. */
  webPreferences: string[];
  /** Source map references found in comments. */
  sourceMaps: string[];
  /** Framework hints derived from imports. */
  frameworks: string[];
  bytes: number;
  lines: number;
  longestLine: number;
  /** True when the file looks like a produced bundle rather than source. */
  minified: boolean;
  comments: number;
}

const ELECTRON_APIS = [
  'ipcMain.handle', 'ipcMain.handleOnce', 'ipcMain.on', 'ipcMain.once',
  'ipcMain.removeHandler', 'ipcMain.removeAllListeners',
  'ipcRenderer.invoke', 'ipcRenderer.send', 'ipcRenderer.sendSync',
  'ipcRenderer.on', 'ipcRenderer.postMessage', 'ipcRenderer.sendToHost',
  'contextBridge.exposeInMainWorld', 'webContents.send', 'webContents.on',
  'BrowserWindow', 'app.whenReady', 'app.on', 'protocol.handle',
  'session.defaultSession', 'globalShortcut.register', 'shell.openExternal',
  'autoUpdater.checkForUpdates', 'Menu.setApplicationMenu',
  'nativeTheme.themeSource', 'dialog.showOpenDialog', 'clipboard.writeText',
  'utilityProcess.fork', 'webContents.executeJavaScript',
];

const WEB_PREFERENCE_KEYS = [
  'nodeIntegration', 'nodeIntegrationInWorker', 'nodeIntegrationInSubFrames',
  'contextIsolation', 'sandbox', 'preload', 'webSecurity', 'allowRunningInsecureContent',
  'spellcheck', 'webviewTag', 'enableRemoteModule', 'additionalArguments',
];

const FRAMEWORK_HINTS: Record<string, string[]> = {
  react: ['react', 'react-dom'],
  vue: ['vue'],
  svelte: ['svelte'],
  angular: ['@angular/core'],
  'preact': ['preact'],
  solid: ['solid-js'],
  'electron': ['electron'],
  'node-fetch': ['node-fetch'],
};

/** Ranges of the source that are not executable code. */
interface Mask { start: number; end: number }

/**
 * Walk the source once, skipping over comments, strings, template literals
 * and regular-expression literals. Returns the masked ranges plus the line
 * index used for position lookups.
 */
function maskSource(text: string): { masked: Mask[]; lineStarts: number[]; commentCount: number } {
  const masked: Mask[] = [];
  const lineStarts: number[] = [0];
  let commentCount = 0;
  let i = 0;
  const len = text.length;

  const lastMeaningful = (): string => {
    for (let k = masked.length ? masked[masked.length - 1].end - 1 : -1; k >= 0; k -= 1) {
      return '';
    }
    return '';
  };
  void lastMeaningful;

  while (i < len) {
    const ch = text[i];

    if (ch === '\n') {
      lineStarts.push(i + 1);
      i += 1;
      continue;
    }

    // Comments
    if (ch === '/' && text[i + 1] === '/') {
      const end = text.indexOf('\n', i);
      const stop = end === -1 ? len : end;
      masked.push({ start: i, end: stop });
      commentCount += 1;
      i = stop;
      continue;
    }
    if (ch === '/' && text[i + 1] === '*') {
      const end = text.indexOf('*/', i + 2);
      const stop = end === -1 ? len : end + 2;
      masked.push({ start: i, end: stop });
      commentCount += 1;
      i = stop;
      continue;
    }

    // Strings
    if (ch === '"' || ch === "'") {
      const end = scanQuoted(text, i, ch);
      masked.push({ start: i, end });
      i = end;
      continue;
    }

    // Template literals (including nested ${ } expressions)
    if (ch === '`') {
      const end = scanTemplate(text, i);
      masked.push({ start: i, end });
      i = end;
      continue;
    }

    // Regex literal: only where a value is expected.
    if (ch === '/' && regexAllowed(text, i)) {
      const end = scanRegex(text, i);
      if (end > i) {
        masked.push({ start: i, end });
        i = end;
        continue;
      }
    }

    i += 1;
  }

  return { masked, lineStarts, commentCount };
}

function scanQuoted(text: string, start: number, quote: string): number {
  let i = start + 1;
  while (i < text.length) {
    const c = text[i];
    if (c === '\\') { i += 2; continue; }
    if (c === quote) return i + 1;
    if (c === '\n') return i; // unterminated: stop at the newline
    i += 1;
  }
  return text.length;
}

function scanTemplate(text: string, start: number): number {
  let i = start + 1;
  while (i < text.length) {
    const c = text[i];
    if (c === '\\') { i += 2; continue; }
    if (c === '`') return i + 1;
    if (c === '$' && text[i + 1] === '{') {
      let depth = 1;
      i += 2;
      while (i < text.length && depth > 0) {
        const d = text[i];
        if (d === '{') depth += 1;
        else if (d === '}') depth -= 1;
        else if (d === '"' || d === "'") { i = scanQuoted(text, i, d); continue; }
        else if (d === '`') { i = scanTemplate(text, i); continue; }
        i += 1;
      }
      continue;
    }
    i += 1;
  }
  return text.length;
}

/** Decide whether a `/` starts a regular expression or is a division. */
function regexAllowed(text: string, index: number): boolean {
  let i = index - 1;
  while (i >= 0) {
    const c = text[i];
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r') { i -= 1; continue; }
    if (c === '=' || c === '(' || c === ',' || c === ':' || c === '[' || c === '{' ||
        c === ';' || c === '!' || c === '&' || c === '|' || c === '?' || c === '+' ||
        c === '-' || c === '*' || c === '%' || c === '~' || c === '^' || c === '<' ||
        c === '>' || c === '}') {
      return true;
    }
    if (/[A-Za-z0-9_$]/.test(c)) {
      // A keyword before the slash means a regex may follow.
      let word = '';
      let k = i;
      while (k >= 0 && /[A-Za-z0-9_$]/.test(text[k])) { word = text[k] + word; k -= 1; }
      return ['return', 'typeof', 'instanceof', 'in', 'of', 'new', 'delete', 'void',
        'case', 'do', 'else', 'yield', 'await', 'throw'].includes(word);
    }
    return false;
  }
  return true;
}

function scanRegex(text: string, start: number): number {
  let i = start + 1;
  let inClass = false;
  while (i < text.length) {
    const c = text[i];
    if (c === '\\') { i += 2; continue; }
    if (c === '\n') return start; // not a regex after all
    if (c === '[') inClass = true;
    else if (c === ']') inClass = false;
    else if (c === '/' && !inClass) {
      i += 1;
      while (i < text.length && /[a-z]/i.test(text[i])) i += 1;
      return i;
    }
    i += 1;
  }
  return start;
}

function isMasked(masked: Mask[], index: number): boolean {
  let lo = 0;
  let hi = masked.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const range = masked[mid];
    if (index < range.start) hi = mid - 1;
    else if (index >= range.end) lo = mid + 1;
    else return true;
  }
  return false;
}

function positionOf(lineStarts: number[], index: number): { line: number; column: number } {
  let lo = 0;
  let hi = lineStarts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (lineStarts[mid] <= index) lo = mid;
    else hi = mid - 1;
  }
  return { line: lo + 1, column: index - lineStarts[lo] + 1 };
}

function lineText(text: string, lineStarts: number[], line: number): string {
  const start = lineStarts[line - 1] ?? 0;
  const end = line < lineStarts.length ? lineStarts[line] - 1 : text.length;
  return text.slice(start, end).trim();
}

function isIdentifierChar(c: string): boolean {
  return /[A-Za-z0-9_$]/.test(c);
}

/** Scan one source file for module edges, IPC channels and framework hints. */
export function scanJsSource(text: string): JsScan {
  const { masked, lineStarts, commentCount } = maskSource(text);
  const scan: JsScan = {
    imports: [], exports: [], requires: [], apis: [],
    channels: { handle: [], on: [], invoke: [], send: [], expose: [] },
    webPreferences: [], sourceMaps: [], frameworks: [],
    bytes: text.length, lines: lineStarts.length, longestLine: 0,
    minified: false, comments: commentCount,
  };

  for (let i = 0; i < lineStarts.length; i += 1) {
    const start = lineStarts[i];
    const end = i + 1 < lineStarts.length ? lineStarts[i + 1] - 1 : text.length;
    const length = end - start;
    if (length > scan.longestLine) scan.longestLine = length;
  }
  scan.minified = scan.longestLine > 4000 && scan.lines < 20;

  // Source maps live in comments, so they are read from the raw text.
  const sourceMapRe = /\/\/[#@]\s*sourceMappingURL=([^\s'"]+)/g;
  let smMatch: RegExpExecArray | null;
  while ((smMatch = sourceMapRe.exec(text)) !== null) {
    scan.sourceMaps.push(smMatch[1]);
  }

  const pushHit = (list: JsHit[], kind: string, value: string, index: number) => {
    const { line, column } = positionOf(lineStarts, index);
    list.push({ kind, value, line, column, text: lineText(text, lineStarts, line) });
  };

  // import / export / require
  const keywords = ['import', 'export', 'require'];
  for (const keyword of keywords) {
    let at = text.indexOf(keyword);
    while (at !== -1) {
      const before = at === 0 ? '' : text[at - 1];
      const after = text[at + keyword.length];
      const boundaryOk = !isIdentifierChar(before) && !isIdentifierChar(after);
      if (boundaryOk && !isMasked(masked, at)) {
        if (keyword === 'require') {
          const spec = nextStringLiteral(text, masked, at + keyword.length);
          if (spec) pushHit(scan.requires, 'require', spec.value, at);
        } else if (keyword === 'import') {
          const spec = nextStringLiteral(text, masked, at + keyword.length);
          if (spec) pushHit(scan.imports, 'import', spec.value, at);
        } else {
          // export ... from 'mod' — only the re-export form has a specifier.
          const between = text.slice(at + keyword.length, specWindow(text, masked, at + keyword.length));
          if (/\bfrom\b/.test(between)) {
            const spec = nextStringLiteral(text, masked, at + keyword.length);
            if (spec) pushHit(scan.exports, 'export-from', spec.value, at);
          }
        }
      }
      at = text.indexOf(keyword, at + keyword.length);
    }
  }

  // Electron and Node APIs
  for (const api of ELECTRON_APIS) {
    let at = text.indexOf(api);
    while (at !== -1) {
      const before = at === 0 ? '' : text[at - 1];
      const after = text[at + api.length];
      if (!isIdentifierChar(before) && !isIdentifierChar(after) && !isMasked(masked, at)) {
        pushHit(scan.apis, api, api, at);
        if (api.startsWith('ipcMain.handle')) {
          const ch = nextStringLiteral(text, masked, at + api.length);
          if (ch) scan.channels.handle.push(ch.value);
        } else if (api.startsWith('ipcMain.on') || api.startsWith('ipcMain.once')) {
          const ch = nextStringLiteral(text, masked, at + api.length);
          if (ch) scan.channels.on.push(ch.value);
        } else if (api.startsWith('ipcRenderer.invoke')) {
          const ch = nextStringLiteral(text, masked, at + api.length);
          if (ch) scan.channels.invoke.push(ch.value);
        } else if (api.startsWith('ipcRenderer.send')) {
          const ch = nextStringLiteral(text, masked, at + api.length);
          if (ch) scan.channels.send.push(ch.value);
        } else if (api.startsWith('contextBridge.exposeInMainWorld')) {
          const ch = nextStringLiteral(text, masked, at + api.length);
          if (ch) scan.channels.expose.push(ch.value);
        }
      }
      at = text.indexOf(api, at + api.length);
    }
  }

  // webPreferences keys
  for (const key of WEB_PREFERENCE_KEYS) {
    let at = text.indexOf(key);
    while (at !== -1) {
      const before = at === 0 ? '' : text[at - 1];
      const after = text[at + key.length];
      if (!isIdentifierChar(before) && !isIdentifierChar(after) && !isMasked(masked, at)) {
        scan.webPreferences.push(key);
      }
      at = text.indexOf(key, at + key.length);
    }
  }
  scan.webPreferences = [...new Set(scan.webPreferences)];

  // Frameworks from the bare specifiers seen in imports/requires.
  const specifiers = new Set(
    [...scan.imports, ...scan.requires].map((hit) => hit.value),
  );
  for (const [framework, names] of Object.entries(FRAMEWORK_HINTS)) {
    if (names.some((name) => specifiers.has(name))) scan.frameworks.push(framework);
  }

  return scan;
}

/** The window in which a module specifier may appear after a keyword. */
function specWindow(text: string, masked: Mask[], from: number): number {
  const limit = Math.min(text.length, from + 400);
  for (let i = from; i < limit; i += 1) {
    if (text[i] === ';' || text[i] === '\n') return i;
  }
  return limit;
}

/** Find the next string literal after a position and return its contents. */
function nextStringLiteral(text: string, masked: Mask[], from: number): { value: string; index: number } | null {
  const limit = Math.min(text.length, from + 400);
  for (let i = from; i < limit; i += 1) {
    const c = text[i];
    if (c !== '"' && c !== "'") continue;
    if (!isMasked(masked, i)) continue;
    const end = scanQuoted(text, i, c);
    const value = text.slice(i + 1, Math.max(i + 1, end - 1));
    return { value: value.replace(/\\(['"`\\])/g, '$1'), index: i };
  }
  return null;
}

export interface AppFileEntry {
  path: string;
  rel: string;
  bytes: number;
  scan: JsScan;
}

export interface JsApplicationAnalysis {
  kind: 'js-application';
  root: string;
  packageName: string | null;
  packageVersion: string | null;
  entryPoint: string | null;
  electron: boolean;
  frameworks: string[];
  files: AppFileEntry[];
  fileCount: number;
  totalBytes: number;
  dependencies: string[];
  ipc: {
    handle: Array<{ channel: string; file: string; line: number }>;
    invoke: Array<{ channel: string; file: string; line: number }>;
    send: Array<{ channel: string; file: string; line: number }>;
    on: Array<{ channel: string; file: string; line: number }>;
    expose: Array<{ channel: string; file: string; line: number }>;
  };
  /** Channels declared on one side but never referenced on the other. */
  unmatchedChannels: string[];
  limitations: string[];
}

const JS_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx', '.mts', '.cts']);
const MAX_SCAN_BYTES = 12 * 1024 * 1024;

/** Analyse a JavaScript / Electron application directory. */
export async function analyzeJsApplication(root: string, files: Array<{ path: string; rel: string; size: number }>): Promise<JsApplicationAnalysis> {
  const limitations: string[] = [];
  const packageJsonPath = `${root}/package.json`;
  let pkg: Record<string, unknown> | null = null;
  try {
    pkg = JSON.parse(await readFile(packageJsonPath, 'utf8')) as Record<string, unknown>;
  } catch {
    pkg = null;
    limitations.push('No readable package.json was found; the entry point and dependency list could not be established.');
  }

  const deps = {
    ...(pkg?.dependencies as Record<string, string> | undefined),
    ...(pkg?.devDependencies as Record<string, string> | undefined),
  };
  const dependencyNames = Object.keys(deps);

  const jsFiles = files.filter((f) => JS_EXTENSIONS.has(f.rel.slice(f.rel.lastIndexOf('.')).toLowerCase()));
  let scanned = 0;
  let skipped = 0;
  const entries: AppFileEntry[] = [];

  for (const file of jsFiles) {
    if (file.size > MAX_SCAN_BYTES) {
      skipped += 1;
      continue;
    }
    let text: string;
    try {
      text = await readFile(file.path, 'utf8');
    } catch {
      skipped += 1;
      continue;
    }
    entries.push({ path: file.path, rel: file.rel, bytes: file.size, scan: scanJsSource(text) });
    scanned += 1;
  }
  if (skipped > 0) {
    limitations.push(`${skipped} script file(s) were larger than ${(MAX_SCAN_BYTES / 1024 / 1024).toFixed(0)} MiB and were not scanned.`);
  }

  const mainField = typeof pkg?.main === 'string' ? (pkg.main as string) : null;
  const entryPoint = mainField ? `${root}/${mainField.replace(/^\.\//, '')}` : null;

  const frameworks = new Set<string>();
  for (const entry of entries) for (const f of entry.scan.frameworks) frameworks.add(f);

  const ipc: JsApplicationAnalysis['ipc'] = { handle: [], invoke: [], send: [], on: [], expose: [] };
  for (const entry of entries) {
    const push = (list: typeof ipc.handle, channels: string[]) => {
      for (const channel of channels) {
        list.push({ channel, file: entry.rel, line: entry.scan.imports.length >= 0 ? findChannelLine(entry, channel) : 0 });
      }
    };
    push(ipc.handle, entry.scan.channels.handle);
    push(ipc.invoke, entry.scan.channels.invoke);
    push(ipc.send, entry.scan.channels.send);
    push(ipc.on, entry.scan.channels.on);
    push(ipc.expose, entry.scan.channels.expose);
  }

  const mainSide = new Set(ipc.handle.map((c) => c.channel));
  const rendererSide = new Set([...ipc.invoke, ...ipc.send, ...ipc.on].map((c) => c.channel));
  const unmatched = [...mainSide].filter((c) => !rendererSide.has(c))
    .concat([...rendererSide].filter((c) => !mainSide.has(c)));

  const electron = 'electron' in deps
    || entries.some((e) => e.scan.apis.some((a) => a.kind.startsWith('ipc') || a.kind.startsWith('contextBridge') || a.kind === 'BrowserWindow'));

  return {
    kind: 'js-application',
    root,
    packageName: typeof pkg?.name === 'string' ? (pkg.name as string) : null,
    packageVersion: typeof pkg?.version === 'string' ? (pkg.version as string) : null,
    entryPoint,
    electron,
    frameworks: [...frameworks],
    files: entries,
    fileCount: entries.length,
    totalBytes: entries.reduce((sum, e) => sum + e.bytes, 0),
    dependencies: dependencyNames,
    ipc,
    unmatchedChannels: [...new Set(unmatched)],
    limitations,
  };
}

function findChannelLine(entry: AppFileEntry, channel: string): number {
  const hit = entry.scan.apis.find((a) => a.text.includes(channel));
  return hit?.line ?? 0;
}

/** Turn a JS application analysis into an Evidence record. */
export function jsApplicationEvidence(analysis: JsApplicationAnalysis): Evidence {
  const facts: Fact[] = [];
  const push = (label: string, value: string | number | boolean) => facts.push({ label, value: String(value) });

  push('app.package', analysis.packageName ?? 'unknown');
  push('app.version', analysis.packageVersion ?? 'unknown');
  push('app.entry_point', analysis.entryPoint ?? 'unknown');
  push('app.electron', analysis.electron);
  push('app.frameworks', analysis.frameworks.join(', ') || 'none detected');
  push('app.script_files', analysis.fileCount);
  push('app.source_bytes', analysis.totalBytes);
  push('app.dependencies', analysis.dependencies.length);
  push('ipc.handled_channels', analysis.ipc.handle.length);
  push('ipc.invoked_channels', analysis.ipc.invoke.length);
  push('ipc.sent_channels', analysis.ipc.send.length);
  push('ipc.exposed_apis', analysis.ipc.expose.length);
  push('ipc.unmatched_channels', analysis.unmatchedChannels.length);

  return makeEvidence({
    kind: 'js-application',
    subject: analysis.root,
    summary:
      `${analysis.packageName ?? 'Unnamed'} ${analysis.packageVersion ?? ''} — ${analysis.fileCount} script file(s), ` +
      `${analysis.dependencies.length} declared dependencies, ${analysis.electron ? 'Electron' : 'no Electron'} detected. ` +
      `${analysis.ipc.handle.length} handled and ${analysis.ipc.invoke.length + analysis.ipc.send.length} invoked IPC channel(s).`,
    facts,
    locations: analysis.ipc.handle.slice(0, 50).map((c) => ({ file: c.file, line: c.line, note: `handles "${c.channel}"` })),
    metrics: [
      { label: 'app.script_files', value: analysis.fileCount },
      { label: 'app.source_bytes', value: analysis.totalBytes },
      { label: 'ipc.channels', value: analysis.ipc.handle.length + analysis.ipc.invoke.length + analysis.ipc.send.length },
    ],
    limitations: analysis.limitations,
    data: {
      package: { name: analysis.packageName, version: analysis.packageVersion, entry: analysis.entryPoint },
      electron: analysis.electron,
      frameworks: analysis.frameworks,
      dependencies: analysis.dependencies,
      ipc: analysis.ipc,
      unmatchedChannels: analysis.unmatchedChannels,
      files: analysis.files.map((f) => ({
        path: f.rel,
        bytes: f.bytes,
        lines: f.scan.lines,
        minified: f.scan.minified,
        imports: f.scan.imports.map((i) => i.value),
        requires: f.scan.requires.map((i) => i.value),
        apis: [...new Set(f.scan.apis.map((a) => a.kind))],
      })),
    },
  });
}
