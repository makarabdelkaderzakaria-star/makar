#!/usr/bin/env node
/**
 * scan-product-strings.mjs — a diagnostic, not part of the product.
 *
 * It answers one question: what does a browser executable actually have in
 * it? Raqib reads the product name and the product version out of the
 * strings a binary carries. When that fails on a real, large executable, it
 * helps to see the strings for yourself.
 *
 * Usage: node scripts/scan-product-strings.mjs <path to executable> [...]
 *
 * It prints, for every file:
 *   - the strings that look like a product name (Brave, Chrome, Edge, …)
 *   - the version-shaped strings that sit next to them
 *   - how far into the file the version resource was found
 */

import { readFile } from 'node:fs/promises';
import { basename } from 'node:path';

const NAMES = [
  'Brave',
  'Brave Browser',
  'Google Chrome',
  'Microsoft Edge',
  'Vivaldi',
  'Chromium',
  'Opera',
  'Opera GX',
];

const NAME_PATTERN = new RegExp(`^(${NAMES.map((n) => n.replace(/ /g, '\\s')).join('|')})$`, 'i');
const VERSION_PATTERN = /^\d+\.\d+\.\d+(\.\d+)?$/;

function isPrintable(byte) {
  return byte >= 0x20 && byte <= 0x7e;
}

/** Every UTF-16LE string in the buffer, with its offset. */
function utf16Strings(buffer, minLength) {
  const found = [];
  for (let i = 0; i + 1 < buffer.length; i += 2) {
    if (!isPrintable(buffer[i]) || buffer[i + 1] !== 0) continue;
    let j = i;
    while (j + 1 < buffer.length && isPrintable(buffer[j]) && buffer[j + 1] === 0) j += 2;
    const chars = (j - i) / 2;
    if (chars >= minLength) {
      found.push({ value: buffer.toString('utf16le', i, j), offset: i });
      i = j - 2;
    }
  }
  return found;
}

/** Every ASCII string in the buffer, with its offset. */
function asciiStrings(buffer, minLength) {
  const found = [];
  let start = -1;
  for (let i = 0; i < buffer.length; i += 1) {
    if (isPrintable(buffer[i])) {
      if (start < 0) start = i;
    } else if (start >= 0) {
      if (i - start >= minLength) found.push({ value: buffer.toString('latin1', start, i), offset: start });
      start = -1;
    }
  }
  if (start >= 0 && buffer.length - start >= minLength) {
    found.push({ value: buffer.toString('latin1', start, buffer.length), offset: start });
  }
  return found;
}

function nearestVersion(strings, offset) {
  let best = null;
  for (const candidate of strings) {
    if (!VERSION_PATTERN.test(candidate.value)) continue;
    const distance = Math.abs(candidate.offset - offset);
    if (!best || distance < best.distance) best = { value: candidate.value, distance, offset: candidate.offset };
  }
  return best;
}

for (const path of process.argv.slice(2)) {
  const buffer = await readFile(path);
  console.log(`\n=== ${basename(path)} (${buffer.length} bytes) ===`);

  for (const [encoding, strings] of [
    ['utf16le', utf16Strings(buffer, 4)],
    ['ascii', asciiStrings(buffer, 4)],
  ]) {
    const names = strings.filter((s) => NAME_PATTERN.test(s.value.trim()));
    if (names.length === 0) continue;
    console.log(`-- ${encoding}: ${names.length} product-name candidate(s)`);
    for (const name of names.slice(0, 12)) {
      const version = nearestVersion(strings, name.offset);
      const percent = ((name.offset / buffer.length) * 100).toFixed(1);
      console.log(
        `   "${name.value}" at 0x${name.offset.toString(16)} (${percent}% in)` +
          (version ? `  nearest version: ${version.value} at 0x${version.offset.toString(16)}` : '  nearest version: none'),
      );
    }
  }

  // The last few kilobytes are where a version resource usually lives.
  const tail = utf16Strings(buffer.subarray(Math.max(0, buffer.length - 65_536)), 4);
  const tailNames = tail.filter((s) => NAME_PATTERN.test(s.value.trim()));
  if (tailNames.length > 0) {
    console.log('-- the last 64 KiB contain:');
    for (const name of tailNames.slice(0, 8)) console.log(`   "${name.value}"`);
  }
}
