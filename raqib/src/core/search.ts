/**
 * Content search across a tree.
 *
 * Literal searches run over Buffers with `indexOf`, which is the fastest
 * path Node offers; regular expressions decode to UTF-8 and use the regex
 * engine. Large trees are split across a pool of worker threads, so a
 * Chromium-sized checkout is searched in parallel instead of one file at a
 * time on the main thread.
 */
import { readFile } from 'node:fs/promises';
import { Worker } from 'node:worker_threads';
import { join } from 'node:path';
import { walk, looksBinary, isTextPath, workerCount } from './util.js';
import { resolveWorkerScript } from './runtime.js';

export interface SearchOptions {
  pattern: string;
  regex?: boolean;
  caseSensitive?: boolean;
  includeExtensions?: string[];
  excludeDirectories?: string[];
  maxResults?: number;
  maxFileBytes?: number;
  contextLines?: number;
}

export interface SearchHit {
  file: string;
  line: number;
  column: number;
  text: string;
  before?: string[];
  after?: string[];
}

export interface SearchResult {
  pattern: string;
  regex: boolean;
  matches: SearchHit[];
  truncated: boolean;
  filesScanned: number;
  filesWithMatches: number;
  elapsedMs: number;
  workers: number;
}

const DEFAULT_MAX_FILE_BYTES = 24 * 1024 * 1024;

/** Search a single file's contents. */
async function searchFile(
  path: string,
  rel: string,
  options: SearchOptions,
): Promise<SearchHit[]> {
  const buffer = await readFile(path);
  if (buffer.length > (options.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES)) return [];
  if (looksBinary(buffer)) return [];

  // Decode once per file: repeated decoding is what makes naive scanners
  // quadratic on large files.
  const text = buffer.toString('utf8');
  const lineStarts = computeLineStarts(text);
  const hits: SearchHit[] = [];
  const limit = options.maxResults ?? 500;
  const contextLines = options.contextLines ?? 0;

  if (!options.regex) {
    if (options.caseSensitive) {
      // Cheap pre-filter: a file without the bytes cannot contain the text.
      if (!buffer.includes(Buffer.from(options.pattern, 'utf8'))) return [];
    }
    const needle = options.caseSensitive ? options.pattern : options.pattern.toLowerCase();
    const haystack = options.caseSensitive ? text : text.toLowerCase();
    let from = 0;
    while (hits.length < limit) {
      const at = haystack.indexOf(needle, from);
      if (at === -1) break;
      const hit = locate(text, lineStarts, at, rel, contextLines);
      if (hit) hits.push(hit);
      from = at + Math.max(1, needle.length);
    }
    return hits;
  }

  const flags = options.caseSensitive ? 'g' : 'gi';
  let regex: RegExp;
  try {
    regex = new RegExp(options.pattern, flags);
  } catch (error) {
    throw new Error(`invalid regular expression: ${(error as Error).message}`);
  }
  let match: RegExpExecArray | null;
  while ((match = regex.exec(text)) !== null) {
    if (hits.length >= limit) break;
    const hit = locate(text, lineStarts, match.index, rel, contextLines);
    if (hit) hits.push(hit);
    if (match[0].length === 0) regex.lastIndex += 1;
  }
  return hits;
}

/** Byte offsets of every line start, computed once per file. */
function computeLineStarts(text: string): number[] {
  const starts = [0];
  for (let i = 0; i < text.length; i += 1) {
    if (text.charCodeAt(i) === 10) starts.push(i + 1);
  }
  return starts;
}

/** Line/column for a character offset, with optional context lines. */
function locate(text: string, starts: number[], offset: number, rel: string, contextLines: number): SearchHit | null {
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (starts[mid] <= offset) lo = mid;
    else hi = mid - 1;
  }
  const line = lo + 1;
  const lineStart = starts[lo];
  const lineEnd = starts[lo + 1] !== undefined ? starts[lo + 1] - 1 : text.length;
  const hit: SearchHit = {
    file: rel,
    line,
    column: offset - lineStart + 1,
    text: text.slice(lineStart, lineEnd).trim().slice(0, 400),
  };
  if (contextLines > 0) {
    hit.before = [];
    hit.after = [];
    for (let i = Math.max(0, lo - contextLines); i < lo; i += 1) {
      hit.before.push(text.slice(starts[i], (starts[i + 1] ?? text.length) - 1).trim());
    }
    for (let i = lo + 1; i < Math.min(starts.length, lo + 1 + contextLines); i += 1) {
      hit.after.push(text.slice(starts[i], (starts[i + 1] ?? text.length) - 1).trim());
    }
  }
  return hit;
}

/** Search every text file under a root directory. */
export async function searchTree(root: string, options: SearchOptions): Promise<SearchResult> {
  const started = performance.now();
  const maxResults = options.maxResults ?? 500;
  const ignore = new Set(options.excludeDirectories ?? []);

  const entries = await walk(root, { ignoreDirs: ignore.size ? ignore : undefined });
  const candidates = entries.filter((e) => {
    if (e.isDirectory) return false;
    if (e.size === 0) return false;
    if (!isTextPath(e.path)) return false;
    if (options.includeExtensions?.length) {
      const ext = e.ext.toLowerCase();
      if (!options.includeExtensions.some((x) => ext === x.toLowerCase())) return false;
    }
    return true;
  });

  const workerFile = resolveWorkerScript();
  const workerCountWanted = Math.min(workerCount(), Math.max(1, Math.ceil(candidates.length / 400)));
  const matches: SearchHit[] = [];
  let filesScanned = 0;
  let filesWithMatches = 0;
  let truncated = false;

  const runInline = async (subset: typeof candidates): Promise<SearchHit[]> => {
    const found: SearchHit[] = [];
    const CONCURRENCY = 24;
    for (let start = 0; start < subset.length; start += CONCURRENCY) {
      if (found.length >= maxResults) { truncated = true; break; }
      const batch = subset.slice(start, start + CONCURRENCY);
      const settled = await Promise.all(batch.map(async (file) => {
        try {
          const hits = await searchFile(file.path, file.rel, { ...options, maxResults: maxResults - found.length });
          return { hits };
        } catch {
          return { hits: [] as SearchHit[] };
        }
      }));
      for (const { hits } of settled) {
        filesScanned += 1;
        if (hits.length) filesWithMatches += 1;
        found.push(...hits);
      }
    }
    return found;
  };

  let usedWorkers = 0;
  if (candidates.length >= 400 && workerCountWanted > 1) {
    try {
      const chunkSize = Math.ceil(candidates.length / workerCountWanted);
      const chunks: typeof candidates[] = [];
      for (let i = 0; i < candidates.length; i += chunkSize) {
        chunks.push(candidates.slice(i, i + chunkSize));
      }
      const results = await Promise.all(chunks.map((chunk) => runInWorker(chunk, options)));
      for (const result of results) {
        filesScanned += result.filesScanned;
        filesWithMatches += result.filesWithMatches;
        for (const hit of result.matches) {
          if (matches.length >= maxResults) { truncated = true; break; }
          matches.push(hit);
        }
      }
      usedWorkers = chunks.length;
    } catch {
      usedWorkers = 0;
      matches.length = 0;
      filesScanned = 0;
      filesWithMatches = 0;
    }
  }

  if (usedWorkers === 0) {
    const found = await runInline(candidates);
    matches.push(...found);
  }

  matches.sort((a, b) => (a.file === b.file ? a.line - b.line : a.file < b.file ? -1 : 1));

  return {
    pattern: options.pattern,
    regex: Boolean(options.regex),
    matches,
    truncated: truncated || matches.length >= maxResults,
    filesScanned,
    filesWithMatches,
    elapsedMs: performance.now() - started,
    // The honest number: zero means the search ran on the main thread, and
    // anything else is the count of worker threads that carried it. Reporting
    // "1" for the inline path would claim a worker that never started.
    workers: usedWorkers,
  };
}

interface WorkerReply {
  matches: SearchHit[];
  filesScanned: number;
  filesWithMatches: number;
}

/** Run one chunk of the search inside a worker thread. */
function runInWorker(files: Array<{ path: string; rel: string }>, options: SearchOptions): Promise<WorkerReply> {
  return new Promise((resolve, reject) => {
    let worker: Worker;
    try {
      worker = new Worker(resolveWorkerScript());
    } catch (error) {
      reject(error);
      return;
    }
    let settled = false;
    worker.on('message', (message: WorkerReply) => {
      settled = true;
      worker.terminate();
      resolve(message);
    });
    worker.on('error', (error) => {
      if (!settled) reject(error);
    });
    worker.on('exit', () => {
      if (!settled) reject(new Error('search worker exited without a result'));
    });
    worker.postMessage({
      files: files.map((f) => ({ path: f.path, rel: f.rel })),
      options: {
        pattern: options.pattern,
        regex: options.regex,
        caseSensitive: options.caseSensitive,
        maxResults: options.maxResults,
        maxFileBytes: options.maxFileBytes,
        contextLines: options.contextLines,
      },
    });
  });
}
