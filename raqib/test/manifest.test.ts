import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readManifest, manifestEvidence } from '../src/core/manifest.js';

const PACKAGE = {
  name: 'demo-app',
  version: '2.3.1',
  description: 'a small demonstration',
  main: 'src/main.js',
  scripts: { build: 'tsc -p .', start: 'node dist/main.js' },
  dependencies: { electron: '31.0.0', 'lodash.merge': '^4.6.2' },
  devDependencies: { typescript: '5.7.2' },
  engines: { node: '>=20' },
  os: ['darwin'],
  cpu: ['x64', 'arm64'],
  bin: { demo: 'bin/demo.js' },
  build: { electronVersion: '31.0.0', electronDist: 'electron' },
};

async function withPackage<T>(fn: (dir: string, path: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(join(tmpdir(), 'raqib-manifest-'));
  try {
    const path = join(dir, 'package.json');
    await writeFile(path, JSON.stringify(PACKAGE, null, 2), 'utf8');
    return await fn(dir, path);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

test('reads the fields a manifest declares', async () => {
  await withPackage(async (_dir, path) => {
    const report = await readManifest(path);
    assert.equal(report.format, 'package-manifest');
    assert.equal(report.name, 'demo-app');
    assert.equal(report.version, '2.3.1');
    assert.equal(report.main, 'src/main.js');
    assert.equal(report.license, null);
    assert.equal(Object.keys(report.dependencies).length, 2);
    assert.equal(Object.keys(report.devDependencies).length, 1);
    assert.equal(Object.keys(report.scripts).length, 2);
    assert.equal(report.bin.demo, 'bin/demo.js');
    assert.deepEqual(report.os, ['darwin']);
    assert.deepEqual(report.cpu, ['x64', 'arm64']);
    assert.equal(report.engines.node, '>=20');
    assert.equal(report.electron?.version, '31.0.0');
  });
});

test('says when a JSON file is not a manifest', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'raqib-manifest-'));
  try {
    const path = join(dir, 'data.json');
    await writeFile(path, JSON.stringify({ hello: 'world', items: [1, 2, 3] }), 'utf8');
    const report = await readManifest(path);
    assert.equal(report.format, 'json');
    assert.equal(report.name, null);
    assert.deepEqual(report.topLevelKeys, ['hello', 'items']);
    assert.equal(report.jsonType, 'object');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('refuses a file that is not JSON at all', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'raqib-manifest-'));
  try {
    const path = join(dir, 'broken.json');
    await writeFile(path, '{ not json', 'utf8');
    await assert.rejects(() => readManifest(path), /not valid JSON/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('the evidence record states what a manifest cannot prove', async () => {
  await withPackage(async (_dir, path) => {
    const evidence = await manifestEvidence(path);
    assert.equal(evidence.kind, 'manifest');
    assert.match(evidence.summary, /demo-app 2\.3\.1/);
    assert.ok(evidence.facts.some((f) => f.label === 'manifest.name' && f.value === 'demo-app'));
    assert.ok(evidence.facts.some((f) => f.label === 'manifest.dependencies' && f.value === '2'));
    assert.ok(evidence.facts.some((f) => f.label === 'manifest.electron_version' && f.value === '31.0.0'));
    assert.ok(evidence.limitations.length >= 2);
    assert.match(evidence.limitations.join(' '), /declares intent/);
  });
});

test('the dependency versions are preserved exactly as written', async () => {
  await withPackage(async (_dir, path) => {
    const report = await readManifest(path);
    assert.equal(report.dependencies.electron, '31.0.0');
    assert.equal(report.dependencies['lodash.merge'], '^4.6.2');
  });
});
