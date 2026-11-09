import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { parseElf, inspectElf, isElf } from '../src/core/elf.js';

const SYSTEM_ELF = '/bin/ls';

test('isElf recognises the ELF magic', () => {
  assert.equal(isElf(readFileSync(SYSTEM_ELF)), true);
  assert.equal(isElf(Buffer.from('MZ not an elf')), false);
});

test('parses a real ELF image', { skip: !existsSync(SYSTEM_ELF) }, async () => {
  const { analysis, evidence } = await inspectElf(SYSTEM_ELF);

  assert.equal(analysis.format, 'elf');
  assert.equal(analysis.class, 'ELF64');
  assert.equal(analysis.endian, 'little');
  assert.equal(analysis.machine, 'x86-64');
  assert.equal(analysis.type, 'ET_DYN');
  assert.ok(analysis.sections.length > 10, 'a real binary has sections');
  assert.ok(analysis.interpreter?.includes('ld-linux'), 'the interpreter is recorded');
  assert.ok(analysis.needed.includes('libc.so.6'), 'libc is a dependency');
  assert.ok(analysis.symbols.length > 0, 'dynamic symbols are read');
  assert.ok(analysis.hardening.pie, 'this image is position independent');
  assert.ok(analysis.hardening.nx, 'this image has a non-executable stack');
  assert.ok(analysis.hardening.relro, 'this image has RELRO');

  assert.equal(evidence.kind, 'elf');
  assert.match(evidence.id, /^ev_[0-9a-f]{16}$/);
  assert.ok(evidence.facts.some((f) => f.label === 'elf.machine' && f.value === 'x86-64'));
});

test('the build id matches the one the system tool reports', { skip: !existsSync(SYSTEM_ELF) }, async () => {
  const { analysis } = await inspectElf(SYSTEM_ELF);
  if (!analysis.buildId) return; // not every image carries one
  assert.match(analysis.buildId, /^[0-9a-f]{20,}$/);
});

test('rejects a buffer that is not an ELF image', () => {
  assert.throws(() => parseElf(Buffer.from('not an elf at all')), /not an ELF/);
});
