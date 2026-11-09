/**
 * The worker half of the search engine. Kept in its own file so it can run on
 * its own thread and read files while the main thread reports progress.
 */
import { parentPort, workerData } from 'node:worker_threads';
import { readFile } from 'node:fs/promises';
import { looksBinary } from './util.js';

interface FileSpec { path: string; rel: string }

interface WorkerOptions {
  pattern: string;
  regex?: boolean;
  caseSensitive?: boolean;
  maxResults?: number;
  maxFileBytes?: number;
  contextLines?: number;
}

const DEFAULT_MAX_FILE_BYTES = 24 * 1024 * 1024;

async function searchFile(spec: FileSpec, options: WorkerOptions): Promise<Array<{ file: string; line: number; column: number; text: string }>> {
  const buffer = await readFile(spec.path);
  if (buffer.length > (options.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES)) return [];
  if (looksBinary(buffer)) return [];

  // Decode once per file.
  const text = buffer.toString('utf8');
  const lineStarts = computeLineStarts(text);
  const hits: Array<{ file: string; line: number; column: number; text: string }> = [];
  const limit = options.maxResults ?? 500;

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
      const hit = locate(text, lineStarts, at, spec.rel);
      if (hit) hits.push(hit);
      from = at + Math.max(1, needle.length);
    }
    return hits;
  }

  const flags = options.caseSensitive ? 'g' : 'gi';
  let regex: RegExp;
  try {
    regex = new RegExp(options.pattern, flags);
  } catch {
    return [];
  }
  let match: RegExpExecArray | null;
  while ((match = regex.exec(text)) !== null) {
    if (hits.length >= limit) break;
    const hit = locate(text, lineStarts, match.index, spec.rel);
    if (hit) hits.push(hit);
    if (match[0].length === 0) regex.lastIndex += 1;
  }
  return hits;
}

function computeLineStarts(text: string): number[] {
  const starts = [0];
  for (let i = 0; i < text.length; i += 1) {
    if (text.charCodeAt(i) === 10) starts.push(i + 1);
  }
  return starts;
}

function locate(text: string, starts: number[], offset: number, rel: string) {
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (starts[mid] <= offset) lo = mid;
    else hi = mid - 1;
  }
  const lineStart = starts[lo];
  const lineEnd = starts[lo + 1] !== undefined ? starts[lo + 1] - 1 : text.length;
  return {
    file: rel,
    line: lo + 1,
    column: offset - lineStart + 1,
    text: text.slice(lineStart, lineEnd).trim().slice(0, 400),
  };
}

async function main(): Promise<void> {
  const { files, options } = workerData as { files: FileSpec[]; options: WorkerOptions };
  const matches: Array<{ file: string; line: number; column: number; text: string }> = [];
  let filesScanned = 0;
  let filesWithMatches = 0;

  // Read and scan in parallel: on a large tree the cost is dominated by
  // waiting on files, not by the scan itself.
  const CONCURRENCY = 24;
  for (let start = 0; start < files.length; start += CONCURRENCY) {
    const batch = files.slice(start, start + CONCURRENCY);
    const settled = await Promise.all(batch.map(async (spec) => {
      try {
        return { spec, hits: await searchFile(spec, options) };
      } catch {
        return { spec, hits: [] as typeof matches };
      }
    }));
    for (const { hits } of settled) {
      filesScanned += 1;
      if (hits.length) filesWithMatches += 1;
      matches.push(...hits);
    }
    if (matches.length >= (options.maxResults ?? 500)) break;
  }
  parentPort?.postMessage({ matches, filesScanned, filesWithMatches });
}

void main();
