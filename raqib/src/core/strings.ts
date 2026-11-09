/**
 * Printable string extraction.
 *
 * Native binaries hide more in their strings than in their symbol tables:
 * feature flags, user-agent fragments, command names, error text. This pulls
 * them out with a single pass, in both ASCII and UTF-16LE.
 */
import { readFile } from 'node:fs/promises';
import { makeEvidence, type Evidence } from './evidence.js';

export interface ExtractedString {
  value: string;
  offset: number;
  encoding: 'ascii' | 'utf16le';
}

export interface StringOptions {
  minLength?: number;
  maxStrings?: number;
  filter?: RegExp;
}

/** Extract printable strings from a buffer. */
export function extractStrings(buffer: Buffer, options: StringOptions = {}): ExtractedString[] {
  const minLength = options.minLength ?? 6;
  const maxStrings = options.maxStrings ?? 20000;
  const out: ExtractedString[] = [];

  // ASCII / UTF-8
  let start = -1;
  for (let i = 0; i <= buffer.length; i += 1) {
    const byte = i < buffer.length ? buffer[i] : 0;
    const printable = byte >= 0x20 && byte <= 0x7e;
    if (printable) {
      if (start === -1) start = i;
    } else if (start !== -1) {
      if (i - start >= minLength) {
        const value = buffer.toString('latin1', start, i);
        if (!options.filter || options.filter.test(value)) {
          out.push({ value, offset: start, encoding: 'ascii' });
        }
      }
      start = -1;
    }
    if (out.length >= maxStrings) return out;
  }

  // UTF-16LE: printable byte followed by a zero byte.
  //
  // The scan has to stay on even offsets: a UTF-16 character is two bytes,
  // so starting one byte off would read every pair the wrong way round and
  // find nothing at all.
  for (let i = 0; i + 1 < buffer.length; i += 2) {
    const first = buffer[i];
    const firstHigh = buffer[i + 1];
    if (!(first >= 0x20 && first <= 0x7e && firstHigh === 0)) continue;

    let j = i;
    const chars: number[] = [];
    while (j + 1 < buffer.length) {
      const byte = buffer[j];
      const high = buffer[j + 1];
      if (byte >= 0x20 && byte <= 0x7e && high === 0) {
        chars.push(byte);
        j += 2;
      } else break;
    }
    if (chars.length >= minLength) {
      const value = Buffer.from(chars).toString('latin1');
      if (!options.filter || options.filter.test(value)) {
        out.push({ value, offset: i, encoding: 'utf16le' });
      }
    }
    // Resume at the end of the string, still on an even offset.
    i = j - 2;
    if (out.length >= maxStrings) break;
  }

  return out;
}

/** Extract strings from a file and return an Evidence record. */
export async function inspectStrings(
  path: string,
  options: StringOptions = {},
): Promise<{ strings: ExtractedString[]; evidence: Evidence }> {
  const buffer = await readFile(path);
  const strings = extractStrings(buffer, options);

  const unique = new Map<string, number>();
  for (const item of strings) unique.set(item.value, (unique.get(item.value) ?? 0) + 1);
  const top = [...unique.entries()].sort((a, b) => b[1] - a[1]).slice(0, 25);

  const evidence = makeEvidence({
    kind: 'strings',
    subject: path,
    summary:
      `${strings.length} printable strings recovered from a ${buffer.length} byte image ` +
      `(${unique.size} distinct).`,
    facts: [
      { label: 'strings.total', value: String(strings.length) },
      { label: 'strings.distinct', value: String(unique.size) },
      { label: 'file.bytes', value: String(buffer.length) },
    ],
    metrics: [
      { label: 'strings.total', value: strings.length },
      { label: 'strings.distinct', value: unique.size },
    ],
    limitations: [
      'String extraction proves what the image contains, not what the code does with it.',
      'Strings that were stripped, compressed or built at runtime are not visible here.',
    ],
    data: {
      strings: strings.slice(0, options.maxStrings ?? 20000),
      mostCommon: top.map(([value, count]) => ({ value, count })),
    },
  });

  return { strings, evidence };
}
