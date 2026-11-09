import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parsePe } from '../src/core/pe.js';
import { createHash } from 'node:crypto';
import { buildPe } from './fixtures/pe.js';

test('parses a PE32+ image', () => {
  const { buffer, expected } = buildPe();
  const analysis = parsePe(buffer, 'sample.exe');

  assert.equal(analysis.format, 'pe');
  assert.equal(analysis.machine, expected.machine);
  assert.equal(analysis.subsystem, expected.subsystem);
  assert.equal(analysis.isDll, false);
  assert.equal(analysis.sections.length, 2);
  assert.equal(analysis.sections[0].name, '.text');
  assert.equal(analysis.sections[1].name, '.rdata');
});

test('reads the import table', () => {
  const { buffer, expected } = buildPe();
  const analysis = parsePe(buffer, 'sample.exe');

  assert.equal(analysis.imports.length, 1);
  assert.equal(analysis.imports[0].dll, 'KERNEL32.dll');
  assert.deepEqual(analysis.imports[0].functions, expected.imports['KERNEL32.dll']);
});

test('reads the export table', () => {
  const { buffer, expected } = buildPe();
  const analysis = parsePe(buffer, 'sample.exe');

  assert.equal(analysis.exports.name, expected.exportName);
  assert.deepEqual(analysis.exports.functions, expected.exports);
});

test('reads the Authenticode certificate table', () => {
  const { buffer, expected } = buildPe();
  const analysis = parsePe(buffer, 'sample.exe');

  assert.ok(analysis.certificate, 'the certificate table is found');
  assert.equal(analysis.certificate?.size, expected.certificateSize);
  assert.equal(analysis.certificate?.type, 'WIN_CERT_TYPE_PKCS_SIGNED_DATA');
  assert.ok(
    analysis.limitations.some((l) => l.includes('not cryptographically verified')),
    'the signature is not claimed to be verified',
  );
});

test('computes the import hash', () => {
  const { buffer } = buildPe();
  const analysis = parsePe(buffer, 'sample.exe');

  // kernel32.createfilew + kernel32.closehandle, lower-cased and concatenated.
  const expected = createHash('md5')
    .update('kernel32.createfilewkernel32.closehandle', 'utf8')
    .digest('hex');
  assert.equal(analysis.imphash, expected);
  assert.match(analysis.imphash, /^[0-9a-f]{32}$/);
});

test('reads the hardening flags', () => {
  const { buffer, expected } = buildPe();
  const analysis = parsePe(buffer, 'sample.exe');

  assert.equal(analysis.hardening.aslr, expected.aslr);
  assert.equal(analysis.hardening.dep, expected.dep);
  assert.equal(analysis.hardening.cfg, expected.cfg);
  assert.equal(analysis.hardening.highEntropyAslr, true);
  assert.equal(analysis.hardening.relocsStripped, false);
});

test('rejects a buffer that is not a PE image', () => {
  assert.throws(() => parsePe(Buffer.from('nope')), /not a PE/);
});
