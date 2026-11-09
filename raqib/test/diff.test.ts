import { test } from 'node:test';
import assert from 'node:assert/strict';
import { makeEvidence } from '../src/core/evidence.js';
import { diffEvidence, diffEvidenceRecord } from '../src/core/diff.js';

const left = makeEvidence({
  kind: 'js-application',
  subject: '/app',
  summary: 'two channels',
  facts: [
    { label: 'app.version', value: '1.0.0' },
    { label: 'ipc.handled_channels', value: '2' },
    { label: 'app.dependencies', value: '5' },
  ],
  locations: [{ file: 'src/main.js', line: 10, note: 'handles "a"' }],
  limitations: ['the renderer was not read'],
});

const right = makeEvidence({
  kind: 'js-application',
  subject: '/app',
  summary: 'three channels',
  facts: [
    { label: 'app.version', value: '1.1.0' },
    { label: 'ipc.handled_channels', value: '3' },
    { label: 'app.frameworks', value: 'react' },
  ],
  locations: [
    { file: 'src/main.js', line: 10, note: 'handles "a"' },
    { file: 'src/main.js', line: 22, note: 'handles "c"' },
  ],
  limitations: [],
});

test('reports what changed between two analyses', () => {
  const diff = diffEvidence(left, right);

  assert.equal(diff.identical, false);
  assert.deepEqual(diff.facts.changed.map((c) => c.label), ['app.version', 'ipc.handled_channels']);
  assert.deepEqual(diff.facts.added.map((f) => f.label), ['app.frameworks']);
  assert.deepEqual(diff.facts.removed.map((f) => f.label), ['app.dependencies']);
  assert.equal(diff.locations.added.length, 1);
  assert.equal(diff.locations.removed.length, 0);
  assert.deepEqual(diff.limitations.added, []);
  assert.deepEqual(diff.limitations.removed, ['the renderer was not read']);
});

test('says two identical analyses are identical', () => {
  const diff = diffEvidence(left, left);
  assert.equal(diff.identical, true);
  assert.match(diff.summary, /identical/);
});

test('the diff becomes an evidence record of its own', () => {
  const record = diffEvidenceRecord(diffEvidence(left, right), '/app ↔ /app');
  assert.equal(record.kind, 'evidence-diff');
  assert.ok(record.facts.some((f) => f.label === 'diff.facts_changed' && f.value === '2'));
  assert.ok(record.facts.some((f) => f.label === 'diff.changed.app.version' && f.value === '1.0.0 → 1.1.0'));
  assert.ok(record.limitations.length > 0);
});
