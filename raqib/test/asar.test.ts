import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readAsarManifest, readAsarFile, asarEvidence } from '../src/core/asar.js';
import { buildAsar } from './fixtures/asar.js';

test('reads an ASAR manifest and its entries', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'raqib-asar-'));
  try {
    const archive = join(dir, 'app.asar');
    buildAsar(archive, {});

    const manifest = await readAsarManifest(archive);

    assert.equal(manifest.fileCount, 2);
    assert.ok(manifest.entries.some((e) => e.path === 'app/main.js'));
    assert.ok(manifest.entries.some((e) => e.path === 'app/lib/util.js'));

    const contents = await readAsarFile(manifest, 'app/main.js');
    assert.ok(contents);
    assert.match(contents!.toString('utf8'), /require\("electron"\)/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('produces evidence for an archive', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'raqib-asar-'));
  try {
    const archive = join(dir, 'app.asar');
    buildAsar(archive, {});
    const { evidence } = await asarEvidence(archive);

    assert.equal(evidence.kind, 'asar');
    assert.match(evidence.id, /^ev_[0-9a-f]{16}$/);
    assert.ok(evidence.facts.some((f) => f.label === 'asar.files' && f.value === '2'));
    assert.ok(evidence.limitations.length > 0, 'unpacked entries are declared as out of scope');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('refuses a file that is not an archive', async () => {
  await assert.rejects(() => readAsarManifest('/etc/hostname'), /ASAR/);
});
