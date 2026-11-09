import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { searchTree } from '../src/core/search.js';
import { indexTree } from '../src/core/indexer.js';
import { selfCommand } from '../src/core/runtime.js';

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

test('the worker threads really do the searching when they are asked for', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'raqib-search-worker-'));
  try {
    // A tree big enough to be worth splitting.
    for (let i = 0; i < 60; i += 1) {
      const sub = join(dir, `dir-${i}`);
      await mkdir(sub, { recursive: true });
      await writeFile(join(sub, `file-${i}.txt`), `needle in file ${i}\n`, 'utf8');
    }
    await writeFile(join(dir, 'top.txt'), 'needle at the top\n', 'utf8');

    const result = await searchTree(dir, { pattern: 'needle', workers: 2 });

    // The worker thread has to have started, not silently fallen back.
    assert.equal(result.workers, 2);
    assert.equal(result.matches.length, 61);
    assert.equal(result.filesScanned, 61);
    assert.equal(result.filesWithMatches, 61);
    assert.ok(result.matches.some((m) => m.file.endsWith('top.txt')));
    assert.ok(result.matches.some((m) => m.file.includes('dir-59')));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('a worker search finds exactly what an inline search finds', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'raqib-search-parity-'));
  try {
    for (let i = 0; i < 40; i += 1) {
      const sub = join(dir, `dir-${i}`);
      await mkdir(sub, { recursive: true });
      await writeFile(join(sub, `file-${i}.txt`), `alpha ${i}\nbeta ${i}\n`, 'utf8');
    }

    const inline = await searchTree(dir, { pattern: 'alpha', maxResults: 1000 });
    const threaded = await searchTree(dir, { pattern: 'alpha', maxResults: 1000, workers: 3 });

    assert.equal(threaded.workers, 3);
    assert.equal(threaded.matches.length, inline.matches.length);
    assert.deepEqual(
      threaded.matches.map((m) => `${m.file}:${m.line}:${m.column}`),
      inline.matches.map((m) => `${m.file}:${m.line}:${m.column}`),
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('the program knows how to start itself again', () => {
  // `raqib setup` writes this into the configuration of a local agent, so
  // it has to point at the program that is actually there.
  const self = selfCommand();
  assert.equal(typeof self.command, 'string');
  assert.ok(self.command.length > 0);
  assert.ok(Array.isArray(self.args));
  assert.equal(self.args[self.args.length - 1], 'mcp');
  if (self.args.length > 1) {
    // The ordinary build: the node that runs the script, then the script.
    // The script is whichever file this build was made from.
    assert.ok(self.args[0].endsWith('.mjs'), self.args[0]);
    assert.ok(existsSync(self.args[0]), self.args[0]);
  }
});
