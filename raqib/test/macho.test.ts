import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { parseMacho, isMacho } from '../src/core/macho.js';

const LC_SEGMENT_64 = 0x19;
const LC_SYMTAB = 0x2;
const LC_LOAD_DYLIB = 0xc;
const LC_UUID = 0x1b;
const LC_MAIN = 0x80000028;

/** A small but genuine arm64 Mach-O executable. */
function buildMacho(): Buffer {
  const segments = 1;
  const sectionCount = 1;
  const symbolCount = 2;

  const segmentSize = 72 + 80 * sectionCount;
  const dylibName = '/usr/lib/libSystem.B.dylib';
  const dylibSize = 24 + dylibName.length + 1;
  const uuidSize = 24;
  const mainSize = 24;
  const symtabSize = 24;

  const headerSize = 32;
  const sizeofcmds = segmentSize + dylibSize + uuidSize + mainSize + symtabSize;

  const fileSize = 0x2000;
  const buffer = Buffer.alloc(fileSize);

  // Mach header (64-bit, little endian)
  buffer.writeUInt32LE(0xfeedfacf, 0);      // magic
  buffer.writeInt32LE(0x0100000c, 4);       // cputype: arm64
  buffer.writeInt32LE(0, 8);                // cpusubtype
  buffer.writeUInt32LE(2, 12);              // filetype: MH_EXECUTE
  buffer.writeUInt32LE(5, 16);              // ncmds
  buffer.writeUInt32LE(sizeofcmds, 20);     // sizeofcmds
  buffer.writeUInt32LE(0x200000, 24);       // flags: MH_PIE
  buffer.writeUInt32LE(0, 28);              // reserved

  let offset = headerSize;

  // LC_SEGMENT_64 __TEXT
  buffer.writeUInt32LE(LC_SEGMENT_64, offset);
  buffer.writeUInt32LE(segmentSize, offset + 4);
  buffer.write('__TEXT', offset + 8, 'latin1');
  buffer.writeBigUInt64LE(0x100000000n, offset + 24);
  buffer.writeBigUInt64LE(0x4000n, offset + 32);
  buffer.writeBigUInt64LE(0n, offset + 40);
  buffer.writeBigUInt64LE(0x4000n, offset + 48);
  buffer.writeUInt32LE(7, offset + 56);     // maxprot
  buffer.writeUInt32LE(5, offset + 60);     // initprot
  buffer.writeUInt32LE(sectionCount, offset + 64);
  buffer.writeUInt32LE(0, offset + 68);
  const section = offset + 72;
  buffer.write('__text', section, 'latin1');
  buffer.write('__TEXT', section + 16, 'latin1');
  buffer.writeBigUInt64LE(0x100000000n, section + 32);
  buffer.writeBigUInt64LE(0x100n, section + 40);
  buffer.writeUInt32LE(0x1000, section + 48);
  buffer.writeUInt32LE(4, section + 52);
  buffer.writeUInt32LE(0x80000400, section + 64);
  offset += segmentSize;

  // LC_LOAD_DYLIB
  buffer.writeUInt32LE(LC_LOAD_DYLIB, offset);
  buffer.writeUInt32LE(dylibSize, offset + 4);
  buffer.writeUInt32LE(24, offset + 8);     // name offset
  buffer.writeUInt32LE(0, offset + 12);
  buffer.writeUInt32LE(0x10000, offset + 16);
  buffer.writeUInt32LE(0x10000, offset + 20);
  buffer.write(dylibName, offset + 24, 'latin1');
  offset += dylibSize;

  // LC_UUID
  buffer.writeUInt32LE(LC_UUID, offset);
  buffer.writeUInt32LE(uuidSize, offset + 4);
  buffer.write('0123456789abcdef', offset + 8, 'latin1');
  offset += uuidSize;

  // LC_MAIN
  buffer.writeUInt32LE(LC_MAIN >>> 0, offset);
  buffer.writeUInt32LE(mainSize, offset + 4);
  buffer.writeBigUInt64LE(0x1000n, offset + 8);
  buffer.writeBigUInt64LE(0n, offset + 16);
  offset += mainSize;

  // LC_SYMTAB
  const symoff = 0x1000;
  const stroff = 0x1100;
  const strtab = Buffer.from('\0_main\0_helper\0', 'latin1');
  buffer.writeUInt32LE(LC_SYMTAB, offset);
  buffer.writeUInt32LE(symtabSize, offset + 4);
  buffer.writeUInt32LE(symoff, offset + 8);
  buffer.writeUInt32LE(symbolCount, offset + 12);
  buffer.writeUInt32LE(stroff, offset + 16);
  buffer.writeUInt32LE(strtab.length, offset + 20);
  offset += symtabSize;

  // symbols
  buffer.writeUInt32LE(1, symoff);          // n_strx
  buffer.writeUInt8(0x0f, symoff + 4);      // N_SECT | N_EXT
  buffer.writeUInt8(1, symoff + 5);         // n_sect
  buffer.writeUInt16LE(0, symoff + 6);
  buffer.writeBigUInt64LE(0x100000000n, symoff + 8);

  buffer.writeUInt32LE(7, symoff + 16);      // n_strx
  buffer.writeUInt8(0x0f, symoff + 20);
  buffer.writeUInt8(1, symoff + 21);
  buffer.writeUInt16LE(0, symoff + 22);
  buffer.writeBigUInt64LE(0x100000010n, symoff + 24);

  strtab.copy(buffer, stroff);

  return buffer;
}

test('recognises the Mach-O magic', () => {
  assert.equal(isMacho(buildMacho()), true);
  assert.equal(isMacho(Buffer.from('not a macho')), false);
});

test('parses a Mach-O executable', () => {
  const analysis = parseMacho(buildMacho(), 'sample');

  assert.equal(analysis.container, 'thin');
  assert.equal(analysis.cpu, 'arm64');
  assert.equal(analysis.bitness, 64);
  assert.equal(analysis.fileType, 'executable');
  assert.equal(analysis.byteOrder, 'little');
  assert.equal(analysis.uuid, '30313233343536373839616263646566');
  assert.equal(analysis.entryPoint, 0x1000);
  assert.deepEqual(analysis.dylibs, ['/usr/lib/libSystem.B.dylib']);
  assert.ok(analysis.flags.includes('PIE'));
  assert.equal(analysis.segments.length, 1);
  assert.equal(analysis.segments[0].name, '__TEXT');
  assert.equal(analysis.segments[0].sections[0].name, '__text');
  assert.equal(analysis.symbolCount, 2);
  assert.deepEqual(analysis.exportedSymbols, ['_main', '_helper']);
});

test('reads a universal binary', () => {
  const thin = buildMacho();
  const fat = Buffer.alloc(8 + 20 + thin.length * 2);
  fat.writeUInt32BE(0xcafebabe, 0);
  fat.writeUInt32BE(2, 4);
  fat.writeInt32BE(0x0100000c, 8);
  fat.writeInt32BE(0, 12);
  fat.writeUInt32BE(28, 16);
  fat.writeUInt32BE(thin.length, 20);
  fat.writeUInt32BE(4, 24);
  fat.writeInt32BE(7, 28);
  fat.writeInt32BE(3, 32);
  fat.writeUInt32BE(28 + thin.length, 36);
  fat.writeUInt32BE(thin.length, 40);
  fat.writeUInt32BE(4, 44);
  thin.copy(fat, 28);
  thin.copy(fat, 28 + thin.length);

  const analysis = parseMacho(fat, 'universal');
  assert.equal(analysis.container, 'universal');
  assert.equal(analysis.architectures.length, 2);
  assert.ok(analysis.limitations.some((l) => l.includes('universal binary')));
});

test('refuses a buffer that is not a Mach-O image', () => {
  assert.throws(() => parseMacho(Buffer.from('nope')), /not a Mach-O/);
});
