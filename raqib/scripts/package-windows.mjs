#!/usr/bin/env node
/**
 * package-windows.mjs — put the Windows executable into a distribution ZIP.
 *
 * There is no dependency here and there is no shell command either: the ZIP
 * is written byte by byte. That keeps the promise that Raqib ships with
 * nothing to install.
 *
 *   node scripts/package-windows.mjs [--out <path>] [--version <v>]
 *
 * The archive holds:
 *   Raqib.exe          the standalone executable
 *   README-WINDOWS.md  how to use it
 *   BUILD-INFO.txt     what it is, and how it was checked
 *   SHA256SUMS         the checksum of the executable
 *   script/raqib.mjs   the same program as a JavaScript file, for anyone
 *   script/searchWorker.mjs   who would rather run it with Node
 */
import { createHash } from 'node:crypto';
import { deflateRawSync } from 'node:zlib';
import { readFileSync, writeFileSync, existsSync, statSync } from 'node:fs';
import { join, basename } from 'node:path';
import { root } from './esbuild-plugins.mjs';

const args = process.argv.slice(2);
function flag(name, fallback = undefined) {
  const index = args.indexOf(`--${name}`);
  return index >= 0 && args[index + 1] ? args[index + 1] : fallback;
}

const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
const VERSION = flag('version', pkg.version);
const OUT = flag('out', join(root, 'dist', `Raqib-${VERSION}-windows-x64.zip`));
const DIST = join(root, 'dist');

// ---------------------------------------------------------------------------
// a ZIP writer, in a few dozen lines
// ---------------------------------------------------------------------------

const CRC_TABLE = (() => {
  const table = new Int32Array(256);
  for (let i = 0; i < 256; i += 1) {
    let c = i;
    for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[i] = c;
  }
  return table;
})();

function crc32(buffer) {
  let c = 0xffffffff;
  for (let i = 0; i < buffer.length; i += 1) c = CRC_TABLE[(c ^ buffer[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

/** A fixed timestamp, so the same input always gives the same archive. */
const DOS_TIME = 0; // 00:00:00
const DOS_DATE = ((2020 - 1980) << 9) | (1 << 5) | 1; // 2020-01-01

function dosDateTime(date = new Date()) {
  const time = (date.getHours() << 11) | (date.getMinutes() << 5) | (date.getSeconds() >> 1);
  const day = ((date.getFullYear() - 1980) << 9) | ((date.getMonth() + 1) << 5) | date.getDate();
  return { time, date: day };
}

function zip(files) {
  const locals = [];
  const centrals = [];
  let offset = 0;

  for (const file of files) {
    const name = Buffer.from(file.name, 'utf8');
    const raw = file.data;
    const deflated = deflateRawSync(raw, { level: 9 });
    // Storing is smaller for an already compressed executable.
    const useDeflate = deflated.length < raw.length;
    const body = useDeflate ? deflated : raw;
    const method = useDeflate ? 8 : 0;
    const crc = crc32(raw);

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4); // version needed
    local.writeUInt16LE(0x0800, 6); // a UTF-8 name
    local.writeUInt16LE(method, 8);
    local.writeUInt16LE(DOS_TIME, 10);
    local.writeUInt16LE(DOS_DATE, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(body.length, 18);
    local.writeUInt32LE(raw.length, 22);
    local.writeUInt16LE(name.length, 26);
    local.writeUInt16LE(0, 28);
    locals.push(local, name, body);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4); // version made by
    central.writeUInt16LE(20, 6); // version needed
    central.writeUInt16LE(0x0800, 8);
    central.writeUInt16LE(method, 10);
    central.writeUInt16LE(DOS_TIME, 12);
    central.writeUInt16LE(DOS_DATE, 14);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(body.length, 20);
    central.writeUInt32LE(raw.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt16LE(0, 30); // extra
    central.writeUInt16LE(0, 32); // comment
    central.writeUInt16LE(0, 34); // disk
    central.writeUInt16LE(0, 36); // internal attributes
    central.writeUInt32LE((0o100644 << 16) >>> 0, 38); // external attributes
    central.writeUInt32LE(offset, 42);
    centrals.push(central, name);

    offset += local.length + name.length + body.length;
  }

  const centralBuffer = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(0, 4);
  end.writeUInt16LE(0, 6);
  end.writeUInt16LE(files.length, 8);
  end.writeUInt16LE(files.length, 10);
  end.writeUInt32LE(centralBuffer.length, 12);
  end.writeUInt32LE(offset, 16);
  end.writeUInt16LE(0, 20);

  return Buffer.concat([...locals, centralBuffer, end]);
}

// ---------------------------------------------------------------------------

const exePath = join(DIST, 'Raqib.exe');
if (!existsSync(exePath)) throw new Error('dist/Raqib.exe is missing — build it first');

const exe = readFileSync(exePath);
const exeSha = createHash('sha256').update(exe).digest('hex');

const readIf = (path) => (existsSync(path) ? readFileSync(path) : null);
const readme = readIf(join(root, 'README-WINDOWS.md'));
const buildInfo = readIf(join(DIST, 'BUILD-INFO.txt'));
const script = readIf(join(DIST, 'raqib.mjs'));
const worker = readIf(join(DIST, 'searchWorker.mjs'));
const results = readIf(join(DIST, 'results.json'));

const sums = `${exeSha}  Raqib.exe\n`;
const files = [
  { name: 'Raqib.exe', data: exe },
  { name: 'README-WINDOWS.md', data: readme ?? Buffer.from('') },
  { name: 'BUILD-INFO.txt', data: buildInfo ?? Buffer.from('') },
  { name: 'SHA256SUMS', data: Buffer.from(sums, 'utf8') },
  { name: 'results.json', data: results ?? Buffer.from('{}\n', 'utf8') },
];
if (script) files.push({ name: 'script/raqib.mjs', data: script });
if (worker) files.push({ name: 'script/searchWorker.mjs', data: worker });

const archive = zip(files);
writeFileSync(OUT, archive);
const zipSha = createHash('sha256').update(archive).digest('hex');

writeFileSync(join(DIST, 'SHA256SUMS'), sums, 'ascii');
writeFileSync(join(DIST, 'SHA256SUMS.zip'), `${zipSha}  ${basename(OUT)}\n`, 'ascii');

console.log(`raqib: packaged ${OUT}`);
console.log(`  size  : ${(archive.length / 1024 / 1024).toFixed(1)} MiB`);
console.log(`  sha256: ${zipSha}`);
console.log(`  exe   : ${exeSha}`);
