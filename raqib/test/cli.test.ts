import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const run = promisify(execFile);
const CLI = join(process.cwd(), 'dist', 'raqib.mjs');

/**
 * A positional argument must be consumed when it is read. If it is not,
 * `compare left right` compares left with left, and `asar file entry`
 * ignores the entry entirely — both of which fail silently.
 */
test('each positional argument is read once and in order', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'raqib-cli-'));
  try {
    await writeFile(join(dir, 'left.json'), JSON.stringify({ name: 'demo', version: '1.0.0', main: 'src/main.js' }), 'utf8');
    await writeFile(join(dir, 'right.json'), JSON.stringify({ name: 'demo', version: '1.1.0', main: 'src/main.js' }), 'utf8');

    const { stdout } = await run(process.execPath, [CLI, 'compare', join(dir, 'left.json'), join(dir, 'right.json')]);
    assert.match(stdout, /manifest\.version: 1\.0\.0\s+->\s+1\.1\.0/);
    assert.doesNotMatch(stdout, /identical/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
