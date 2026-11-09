/**
 * One place that decides how a path is analysed.
 *
 * The MCP server, the command line and the console all dispatch through
 * here, so a new format is supported everywhere at once.
 */
import { readFile, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { inspectElf } from './elf.js';
import { inspectPe } from './pe.js';
import { inspectMacho } from './macho.js';
import { analyzeJsApplication, jsApplicationEvidence } from './js.js';
import { indexTree } from './indexer.js';
import { analyzeChromiumTree, chromiumTreeEvidence, identifyBrowser, browserIdentityEvidence } from './chromium.js';
import { inspectStrings } from './strings.js';
import { asarEvidence } from './asar.js';
import { readSourceMap, sourceMapEvidence } from './sourcemap.js';
import { manifestEvidence } from './manifest.js';
import { walk } from './util.js';
import { makeEvidence, type Evidence } from './evidence.js';

export type TargetKind =
  | 'auto'
  | 'elf'
  | 'pe'
  | 'macho'
  | 'js'
  | 'asar'
  | 'chromium'
  | 'browser'
  | 'strings'
  | 'index'
  | 'sourcemap'
  | 'manifest';

export const TARGET_KINDS: TargetKind[] = [
  'auto', 'elf', 'pe', 'macho', 'js', 'asar', 'chromium', 'browser', 'strings', 'index', 'sourcemap', 'manifest',
];

export function isElf(buffer: Buffer): boolean {
  return buffer.length > 4 && buffer.readUInt32BE(0) === 0x7f454c46;
}

export function isPe(buffer: Buffer): boolean {
  return buffer.length > 0x40 && buffer[0] === 0x4d && buffer[1] === 0x5a;
}

export function isMachoFile(buffer: Buffer): boolean {
  if (buffer.length < 8) return false;
  const magic = buffer.readUInt32BE(0);
  return magic === 0xfeedface || magic === 0xcefaedfe || magic === 0xfeedfacf
    || magic === 0xcffaedfe || magic === 0xcafebabe || magic === 0xbebafeca || magic === 0xcafebabf;
}

export function isAsar(buffer: Buffer): boolean {
  return buffer.length > 16 && buffer.readUInt32LE(0) === 4;
}

/** Whether a JSON file looks like a package manifest rather than any other JSON. */
export function looksLikeManifest(buffer: Buffer): boolean {
  const head = buffer.subarray(0, 4096).toString('utf8');
  if (!head.includes('"name"')) return false;
  return /"(dependencies|devDependencies|main|version|scripts|bin|engines)"\s*:/.test(head);
}

/** Analyse a path, dispatching on what it actually is. */
export async function analyzeTarget(path: string, kind: TargetKind = 'auto'): Promise<Evidence> {
  const info = await stat(path);

  if (info.isDirectory()) {
    if (kind === 'browser') {
      return browserIdentityEvidence(await identifyBrowser(path));
    }
    if (kind === 'chromium') {
      return chromiumTreeEvidence(await analyzeChromiumTree(path));
    }
    if (kind === 'index') {
      return treeIndexEvidence(path);
    }
    if (kind === 'auto') {
      const entries = await walk(path);
      const files = entries.filter((e) => !e.isDirectory);
      const looksChromium = files.some((f) => f.rel.startsWith('chrome/') || f.rel.startsWith('content/'))
        || files.some((f) => f.rel.endsWith('.gn') || f.rel.endsWith('DEPS'));
      if (looksChromium && files.length > 200) {
        return chromiumTreeEvidence(await analyzeChromiumTree(path));
      }
      const hasScripts = files.some((f) => /\.(js|mjs|cjs|jsx|ts|tsx)$/i.test(f.rel));
      if (!hasScripts) return treeIndexEvidence(path);
    }
    const entries = await walk(path);
    const files = entries.filter((e) => !e.isDirectory).map((e) => ({ path: e.path, rel: e.rel, size: e.size }));
    return jsApplicationEvidence(await analyzeJsApplication(path, files));
  }

  const buffer = await readFile(path);

  if (kind === 'elf') return (await inspectElf(path)).evidence;
  if (kind === 'pe') return (await inspectPe(path)).evidence;
  if (kind === 'macho') return (await inspectMacho(path)).evidence;
  if (kind === 'asar') return (await asarEvidence(path)).evidence;
  if (kind === 'sourcemap') return sourceMapEvidence(await readSourceMap(path));
  if (kind === 'manifest') return manifestEvidence(path);
  if (kind === 'strings') return (await inspectStrings(path, { maxStrings: 20000 })).evidence;
  if (kind === 'index') return treeIndexEvidence(path);

  if (isElf(buffer)) return (await inspectElf(path)).evidence;
  if (isPe(buffer)) return (await inspectPe(path)).evidence;
  if (isMachoFile(buffer)) return (await inspectMacho(path)).evidence;
  if (isAsar(buffer)) {
    try {
      return (await asarEvidence(path)).evidence;
    } catch {
      /* not an archive after all */
    }
  }
  if (path.endsWith('.map')) return sourceMapEvidence(await readSourceMap(path));
  if (path.endsWith('.json') && looksLikeManifest(buffer)) return manifestEvidence(path);
  return (await inspectStrings(path, { maxStrings: 20000 })).evidence;
}

/** The inventory of a tree, as an Evidence record. */
export async function treeIndexEvidence(path: string): Promise<Evidence> {
  const index = await indexTree(path);
  return makeEvidence({
    kind: 'tree-index',
    subject: path,
    summary:
      `${index.fileCount} files and ${index.directoryCount} directories (${index.totalBytes} bytes); ` +
      `top languages: ${index.languages.slice(0, 4).map((l) => `${l.language} (${l.files})`).join(', ') || 'none'}.`,
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
}

/** The source map of a bundle, as an Evidence record. */
export async function sourceMapReportEvidence(path: string): Promise<Evidence> {
  return sourceMapEvidence(await readSourceMap(path));
}
