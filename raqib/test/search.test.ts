import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { searchTree } from '../src/core/search.js';
import { indexTree } from '../src/core/indexer.js';

async function fixture(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'raqib-search-'));
  await mkdir(join(dir, 'src'), { recursive: true });
  await writeFile(join(dir, 'src', 'main.js'), [
    "const { app } = require('electron');",
    "ipcMain.handle('secret:open', () => 'ok');",
    "console.log('nothing to see');",
  ].join('\n'), 'utf8');
  await writeFile(join(dir, 'src', 'helper.ts'), [
    'export function openSecret() {',
    "  return 'secret:open';",
    '}',
  ].join('\n'), 'utf8');
  await writeFile(join(dir, 'README.md'), '# Fixture\n\nA secret:open mention.\n', 'utf8');
  return dir;
}

test('finds literal matches with their position', async () => {
  const dir = await fixture();
  try {
    const result = await searchTree(dir, { pattern: 'secret:open' });

    assert.equal(result.matches.length, 3);
    const hit = result.matches.find((m) => m.file === 'src/main.js');
    assert.ok(hit);
    assert.equal(hit.line, 2);
    assert.equal(hit.column, 17);
    assert.equal(result.filesScanned, 3);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('is case-insensitive by default and case-sensitive on request', async () => {
  const dir = await fixture();
  try {
    const loose = await searchTree(dir, { pattern: 'SECRET:OPEN' });
    assert.equal(loose.matches.length, 3);

    const strict = await searchTree(dir, { pattern: 'SECRET:OPEN', caseSensitive: true });
    assert.equal(strict.matches.length, 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('supports regular expressions', async () => {
  const dir = await fixture();
  try {
    const result = await searchTree(dir, { pattern: 'secret:\\w+', regex: true });
    assert.ok(result.matches.length >= 3);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('returns context lines when asked', async () => {
  const dir = await fixture();
  try {
    const result = await searchTree(dir, { pattern: 'secret:open', contextLines: 1 });
    const hit = result.matches.find((m) => m.file === 'src/helper.ts');
    assert.ok(hit?.before?.length);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('indexes a tree by language and size', async () => {
  const dir = await fixture();
  try {
    const index = await indexTree(dir);

    assert.equal(index.fileCount, 3);
    assert.equal(index.directoryCount, 1);
    const languages = index.languages.map((l) => l.language);
    assert.ok(languages.includes('JavaScript'));
    assert.ok(languages.includes('TypeScript'));
    assert.ok(languages.includes('Markdown'));
    assert.ok(index.topLevel.some((t) => t.name === 'src'));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
