import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  parseSourceMap,
  parseMappings,
  originalPositionFor,
  generatedPositionFor,
  findSourceMapReference,
  readSourceMap,
  sourceMapEvidence,
} from '../src/core/sourcemap.js';

/**
 * A three-line map, with the meaning spelled out:
 *   line 1, column 0 → src/a.ts, line 1, column 1
 *   line 2, column 0 → src/a.ts, line 2, column 1
 *   line 3, column 0 → src/b.ts, line 2, column 1
 */
const MAPPINGS = 'AAAA;AACA;ACAA';

test('parses the mappings string', () => {
  const lines = parseMappings(MAPPINGS);
  assert.equal(lines.length, 3);
  assert.equal(lines[0][0].generatedColumn, 0);
  assert.equal(lines[0][0].sourceIndex, 0);
  assert.equal(lines[0][0].originalLine, 0);
  assert.equal(lines[0][0].originalColumn, 0);
  assert.equal(lines[1][0].originalLine, 1);
  assert.equal(lines[2][0].sourceIndex, 1);
});

test('maps a generated position back to the original file', () => {
  const map = parseSourceMap(JSON.stringify({
    version: 3,
    file: 'bundle.js',
    sources: ['src/a.ts', 'src/b.ts'],
    names: [],
    mappings: MAPPINGS,
  }));

  const original = originalPositionFor(map, { line: 2, column: 10 });
  assert.ok(original);
  assert.equal(original?.source, 'src/a.ts');
  assert.equal(original?.line, 2);
  assert.equal(original?.column, 1);

  const other = originalPositionFor(map, { line: 3, column: 0 });
  assert.equal(other?.source, 'src/b.ts');
  assert.equal(other?.line, 2);
});

test('maps an original position forward into the bundle', () => {
  const map = parseSourceMap(JSON.stringify({
    version: 3,
    sources: ['src/a.ts', 'src/b.ts'],
    names: [],
    mappings: MAPPINGS,
  }));

  const generated = generatedPositionFor(map, { source: 'src/a.ts', line: 2 });
  assert.ok(generated);
  assert.equal(generated?.line, 2);
  assert.equal(generated?.column, 1);

  const fromB = generatedPositionFor(map, { source: 'src/b.ts', line: 2 });
  assert.equal(fromB?.line, 3);
});

test('finds the sourceMappingURL comment', () => {
  assert.equal(findSourceMapReference('code\n//# sourceMappingURL=bundle.js.map\n'), 'bundle.js.map');
  assert.equal(findSourceMapReference('code\n'), null);
});

test('reads the map of a bundle and lists the original sources', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'raqib-map-'));
  try {
    const map = {
      version: 3,
      file: 'bundle.js',
      sources: ['../src/a.ts', '../src/b.ts'],
      sourcesContent: ['export const a = 1;', 'export const b = 2;'],
      names: [],
      mappings: MAPPINGS,
    };
    await writeFile(join(dir, 'bundle.js.map'), JSON.stringify(map), 'utf8');
    await writeFile(join(dir, 'bundle.js'), 'const x = 1;\n//# sourceMappingURL=bundle.js.map\n', 'utf8');

    const report = await readSourceMap(join(dir, 'bundle.js'));
    assert.equal(report.originalSources.length, 2);
    assert.equal(report.originalSources[0].hasContent, true);
    assert.equal(report.map?.sources.length, 2);

    const evidence = sourceMapEvidence(report);
    assert.equal(evidence.kind, 'source-map');
    assert.ok(evidence.facts.some((f) => f.label === 'sourcemap.original_sources' && f.value === '2'));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('says so when a bundle has no source map', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'raqib-map-'));
  try {
    await writeFile(join(dir, 'plain.js'), 'const x = 1;\n', 'utf8');
    const report = await readSourceMap(join(dir, 'plain.js'));
    assert.equal(report.map, null);
    assert.ok(report.limitations.length > 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('refuses a map that is not version 3', () => {
  assert.throws(() => parseSourceMap(JSON.stringify({ version: 2 })), /unsupported source map version/);
});

test('falls back to the nearest preceding mapping when a line has none', () => {
  const map = parseSourceMap(JSON.stringify({
    version: 3,
    file: 'bundle.js',
    sources: ['../src/a.ts'],
    sourcesContent: ['export const a = 1;'],
    names: [],
    mappings: 'AAAA',
  }));

  // line 1 is mapped exactly
  const exact = originalPositionFor(map, { line: 1, column: 0 });
  assert.equal(exact?.source, '../src/a.ts');
  assert.equal(exact?.approximate, false);

  // line 5 carries no mapping at all — the nearest preceding one is used
  const nearest = originalPositionFor(map, { line: 5, column: 0 });
  assert.equal(nearest?.source, '../src/a.ts');
  assert.equal(nearest?.line, 1);
  assert.equal(nearest?.approximate, true);
});

test('a map with no mapping at all resolves to nothing rather than guessing', () => {
  const map = parseSourceMap(JSON.stringify({
    version: 3,
    file: 'bundle.js',
    sources: ['../src/a.ts'],
    sourcesContent: ['export const a = 1;'],
    names: [],
    mappings: '',
  }));
  assert.equal(originalPositionFor(map, { line: 3, column: 0 }), null);
});
