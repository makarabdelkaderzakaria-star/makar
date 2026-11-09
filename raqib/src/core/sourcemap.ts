/**
 * Source map resolution (version 3).
 *
 * A minified bundle is unreadable; the source map is the only way back to the
 * code that produced it. This reads the map, maps a position in the bundle
 * back to the original file, and maps an original position forward into the
 * bundle — both directions, because "which file is this?" and "where in the
 * bundle did this come from?" are the two questions an agent actually asks.
 */
import { readFile } from 'node:fs/promises';
import { dirname, isAbsolute, resolve } from 'node:path';
import { makeEvidence, type Evidence, type Fact } from './evidence.js';

export interface SourceMapSegment {
  /** Column in the generated file. */
  generatedColumn: number;
  /** Index into `sources`, or null when the segment has no original position. */
  sourceIndex: number | null;
  /** Line in the original file (0-based), or null. */
  originalLine: number | null;
  /** Column in the original file (0-based), or null. */
  originalColumn: number | null;
  /** Index into `names`, or null. */
  nameIndex: number | null;
}

export interface SourceMap {
  version: number;
  file: string | null;
  sourceRoot: string | null;
  sources: string[];
  sourcesContent: Array<string | null>;
  names: string[];
  /** One entry per generated line, each a list of segments. */
  lines: SourceMapSegment[][];
  /** The raw `mappings` string, kept for the record. */
  mappings: string;
}

const BASE64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

/**
 * Decode one base64 VLQ value. Returns the value and the number of
 * *characters* it consumed — the caller slices the segment with it.
 */
function decodeVlq(segment: string): { value: number; length: number } | null {
  let shift = 0;
  let result = 0;
  for (let i = 0; i < segment.length; i += 1) {
    const digit = BASE64.indexOf(segment[i]);
    if (digit === -1) return null;
    const hasContinuation = (digit & 32) !== 0;
    result += (digit & 31) << shift;
    if (hasContinuation) {
      shift += 5;
      continue;
    }
    const shouldNegate = result & 1;
    result >>>= 1;
    return { value: shouldNegate ? -result : result, length: i + 1 };
  }
  return null;
}

/** Parse a `mappings` string into per-line segments. */
export function parseMappings(mappings: string): SourceMapSegment[][] {
  const lines: SourceMapSegment[][] = [];
  let sourceIndex = 0;
  let originalLine = 0;
  let originalColumn = 0;
  let nameIndex = 0;

  for (const group of mappings.split(';')) {
    const segments: SourceMapSegment[] = [];
    let generatedColumn = 0;
    if (group.length > 0) {
      for (const piece of group.split(',')) {
        if (!piece) continue;
        const fields: number[] = [];
        let rest = piece;
        while (rest.length > 0) {
          const decoded = decodeVlq(rest);
          if (!decoded) break;
          fields.push(decoded.value);
          rest = rest.slice(decoded.length);
        }
        if (fields.length === 0) continue;
        generatedColumn += fields[0];
        if (fields.length === 1) {
          segments.push({ generatedColumn, sourceIndex: null, originalLine: null, originalColumn: null, nameIndex: null });
          continue;
        }
        sourceIndex += fields[1];
        originalLine += fields[2];
        originalColumn += fields[3];
        let name: number | null = null;
        if (fields.length >= 5) {
          nameIndex += fields[4];
          name = nameIndex;
        }
        segments.push({
          generatedColumn,
          sourceIndex,
          originalLine,
          originalColumn,
          nameIndex: name,
        });
      }
    }
    lines.push(segments);
  }
  return lines;
}

/** Parse a source map document. */
export function parseSourceMap(text: string): SourceMap {
  let document: Record<string, unknown>;
  try {
    document = JSON.parse(text) as Record<string, unknown>;
  } catch (error) {
    throw new Error(`invalid source map: ${(error as Error).message}`);
  }
  const version = Number(document.version ?? 0);
  if (version !== 3) throw new Error(`unsupported source map version ${version}`);

  const sources = Array.isArray(document.sources) ? (document.sources as string[]) : [];
  const sourcesContent = Array.isArray(document.sourcesContent)
    ? (document.sourcesContent as Array<string | null>)
    : [];
  const names = Array.isArray(document.names) ? (document.names as string[]) : [];
  const mappings = typeof document.mappings === 'string' ? document.mappings : '';

  return {
    version,
    file: typeof document.file === 'string' ? document.file : null,
    sourceRoot: typeof document.sourceRoot === 'string' ? document.sourceRoot : null,
    sources,
    sourcesContent,
    names,
    lines: parseMappings(mappings),
    mappings,
  };
}

/**
 * The original position behind a position in the generated file.
 *
 * When the exact line carries no mapping — a comment, a blank line, a
 * bundler artefact — the nearest preceding mapping is returned and marked as
 * approximate, because "which file is this?" is more useful than "unknown".
 */
export function originalPositionFor(
  map: SourceMap,
  position: { line: number; column: number },
): { source: string; line: number; column: number; name: string | null; approximate: boolean } | null {
  for (let lineIndex = position.line - 1; lineIndex >= 0; lineIndex -= 1) {
    const segments = map.lines[lineIndex];
    if (!segments || segments.length === 0) continue;

    // The segment with the greatest generatedColumn <= the wanted column.
    let chosen: SourceMapSegment | null = null;
    for (const segment of segments) {
      if (lineIndex === position.line - 1 && segment.generatedColumn > position.column) break;
      if (segment.sourceIndex === null) continue;
      chosen = segment;
    }
    if (!chosen || chosen.sourceIndex === null || chosen.originalLine === null) continue;

    const source = map.sources[chosen.sourceIndex];
    if (source === undefined) continue;

    return {
      source: map.sourceRoot ? `${map.sourceRoot.replace(/\/$/, '')}/${source}` : source,
      line: chosen.originalLine + 1,
      column: (chosen.originalColumn ?? 0) + 1,
      name: chosen.nameIndex !== null ? map.names[chosen.nameIndex] ?? null : null,
      approximate: lineIndex !== position.line - 1,
    };
  }
  return null;
}

/** Where in the generated file an original position ended up. */
export function generatedPositionFor(
  map: SourceMap,
  position: { source: string; line: number; column?: number },
): { line: number; column: number } | null {
  const wanted = normaliseSource(position.source);
  let best: { line: number; column: number } | null = null;

  for (let lineIndex = 0; lineIndex < map.lines.length; lineIndex += 1) {
    for (const segment of map.lines[lineIndex]) {
      if (segment.sourceIndex === null || segment.originalLine === null) continue;
      const source = map.sources[segment.sourceIndex];
      if (source === undefined) continue;
      if (normaliseSource(source) !== wanted) continue;
      if (segment.originalLine + 1 !== position.line) continue;
      const column = (segment.originalColumn ?? 0) + 1;
      if (position.column !== undefined && column > position.column) continue;
      if (!best || column > best.column) {
        best = { line: lineIndex + 1, column };
      }
    }
  }
  return best;
}

function normaliseSource(source: string): string {
  return source.replace(/^\.\//, '').replace(/^webpack:\/\//, '').replace(/^file:\/\//, '');
}

/** The `//# sourceMappingURL=` reference inside a file, if any. */
export function findSourceMapReference(text: string): string | null {
  const match = /\/\/[#@]\s*sourceMappingURL=([^\s'"]+)/.exec(text);
  return match ? match[1] : null;
}

/** Resolve a source map reference against the file that carried it. */
export function resolveMapPath(reference: string, bundlePath: string): string {
  if (reference.startsWith('data:')) return reference;
  if (isAbsolute(reference)) return reference;
  return resolve(dirname(bundlePath), reference);
}

export interface SourceMapReport {
  kind: 'source-map';
  bundle: string;
  mapPath: string | null;
  map: SourceMap | null;
  /** The original files the bundle was built from. */
  originalSources: Array<{ path: string; hasContent: boolean; bytes: number }>;
  limitations: string[];
}

/**
 * Read a source map for a bundle: either the bundle itself (which names its
 * map) or a `.map` file directly.
 */
export async function readSourceMap(path: string): Promise<SourceMapReport> {
  const limitations: string[] = [];
  let bundle = path;
  let mapPath: string | null = null;
  let mapText: string | null = null;

  if (path.endsWith('.map')) {
    mapPath = path;
    mapText = await readFile(path, 'utf8');
  } else {
    const text = await readFile(path, 'utf8');
    const reference = findSourceMapReference(text);
    if (!reference) {
      limitations.push('No sourceMappingURL comment was found in this file, so it has no source map.');
      return { kind: 'source-map', bundle: path, mapPath: null, map: null, originalSources: [], limitations };
    }
    if (reference.startsWith('data:')) {
      const comma = reference.indexOf(',');
      const payload = reference.slice(comma + 1);
      try {
        mapText = Buffer.from(payload, reference.includes('base64') ? 'base64' : 'utf8').toString('utf8');
      } catch {
        limitations.push('The inline source map could not be decoded.');
      }
      mapPath = `${path} (inline)`;
    } else {
      mapPath = resolveMapPath(reference, path);
      try {
        mapText = await readFile(mapPath, 'utf8');
      } catch {
        limitations.push(`The source map "${reference}" is named but could not be read at ${mapPath}.`);
      }
    }
  }

  if (!mapText) {
    return { kind: 'source-map', bundle, mapPath, map: null, originalSources: [], limitations };
  }

  let map: SourceMap;
  try {
    map = parseSourceMap(mapText);
  } catch (error) {
    limitations.push((error as Error).message);
    return { kind: 'source-map', bundle, mapPath, map: null, originalSources: [], limitations };
  }

  const originalSources = map.sources.map((source, index) => ({
    path: map.sourceRoot ? `${map.sourceRoot.replace(/\/$/, '')}/${source}` : source,
    hasContent: typeof map.sourcesContent[index] === 'string',
    bytes: map.sourcesContent[index]?.length ?? 0,
  }));

  const embedded = originalSources.filter((s) => s.hasContent).length;
  if (embedded === 0) {
    limitations.push('The map has no sourcesContent, so the original code is not inside the map and only the file names are known.');
  }

  return { kind: 'source-map', bundle, mapPath, map, originalSources, limitations };
}

/** Evidence for a source map report. */
export function sourceMapEvidence(report: SourceMapReport): Evidence {
  const facts: Fact[] = [];
  const push = (label: string, value: string | number | boolean) => facts.push({ label, value: String(value) });

  push('sourcemap.bundle', report.bundle);
  push('sourcemap.file', report.mapPath ?? 'none');
  push('sourcemap.original_sources', report.originalSources.length);
  push('sourcemap.embedded_sources', report.originalSources.filter((s) => s.hasContent).length);
  push('sourcemap.generated_lines', report.map?.lines.length ?? 0);

  return makeEvidence({
    kind: 'source-map',
    subject: report.bundle,
    summary: report.map
      ? `Source map with ${report.originalSources.length} original file(s) across ${report.map.lines.length} generated line(s); ` +
        `${report.originalSources.filter((s) => s.hasContent).length} of them carry their source inline.`
      : 'No source map could be read for this file.',
    facts,
    locations: report.originalSources.slice(0, 100).map((s) => ({ file: s.path, note: s.hasContent ? 'source is embedded in the map' : 'source is not embedded' })),
    metrics: [
      { label: 'sourcemap.original_sources', value: report.originalSources.length },
      { label: 'sourcemap.generated_lines', value: report.map?.lines.length ?? 0 },
    ],
    limitations: report.limitations,
    data: {
      mapPath: report.mapPath,
      originalSources: report.originalSources,
      sources: report.map?.sources ?? [],
      names: report.map?.names.slice(0, 500) ?? [],
      file: report.map?.file ?? null,
    },
  });
}
