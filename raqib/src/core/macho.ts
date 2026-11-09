/**
 * A self-contained Mach-O reader — the third executable format, for macOS
 * targets. Thin and universal ("fat") binaries, 32- and 64-bit.
 *
 * What it proves: the architecture, the load commands, the dynamic libraries
 * a binary needs, the sections, the UUID, the entry point, and the symbol
 * table.
 */
import { readFile } from 'node:fs/promises';
import { makeEvidence, type Evidence, type Fact } from './evidence.js';

const MH_MAGIC = 0xfeedface;
const MH_CIGAM = 0xcefaedfe;
const MH_MAGIC_64 = 0xfeedfacf;
const MH_CIGAM_64 = 0xcffaedfe;
const FAT_MAGIC = 0xcafebabe;
const FAT_CIGAM = 0xbebafeca;
const FAT_MAGIC_64 = 0xcafebabf;

const LC_SEGMENT = 0x1;
const LC_SYMTAB = 0x2;
const LC_LOAD_DYLIB = 0xc;
const LC_ID_DYLIB = 0xd;
const LC_UUID = 0x1b;
const LC_LOAD_WEAK_DYLIB = 0x80000018;
const LC_REEXPORT_DYLIB = 0x8000001f;
const LC_RPATH = 0x8000001c;
const LC_CODE_SIGNATURE = 0x1d;
const LC_SEGMENT_64 = 0x19;
const LC_VERSION_MIN_MACOSX = 0x24;
const LC_FUNCTION_STARTS = 0x26;
const LC_MAIN = 0x80000028;
const LC_BUILD_VERSION = 0x32;
const LC_DYLD_INFO_ONLY = 0x80000022;

const CPU_NAMES: Record<number, string> = {
  7: 'x86', 12: 'arm', 0x01000007: 'x86-64', 0x0100000c: 'arm64',
};

const FILETYPE_NAMES: Record<number, string> = {
  1: 'object', 2: 'executable', 3: 'fixed VM library', 4: 'core',
  5: 'preloaded VM library', 6: 'dynamic library', 7: 'dynamic linker',
  8: 'bundle', 9: 'dynamic library stub', 10: 'dsym', 11: 'kext',
};

const PLATFORM_NAMES: Record<number, string> = {
  1: 'macOS', 2: 'iOS', 3: 'tvOS', 4: 'watchOS', 6: 'macCatalyst', 7: 'iOS simulator',
};

export interface MachoSection {
  name: string;
  segment: string;
  address: number;
  size: number;
  offset: number;
  flags: string;
}

export interface MachoSegment {
  name: string;
  vmAddress: number;
  vmSize: number;
  fileOffset: number;
  fileSize: number;
  sections: MachoSection[];
}

export interface MachoAnalysis {
  format: 'macho';
  path: string;
  fileSize: number;
  /** "thin" for a single architecture, "universal" for a fat binary. */
  container: 'thin' | 'universal';
  architectures: Array<{
    cpu: string;
    cpuType: number;
    fileType: string;
    offset: number;
    size: number;
  }>;
  cpu: string;
  fileType: string;
  bitness: 32 | 64;
  byteOrder: 'little' | 'big';
  flags: string[];
  entryPoint: number | null;
  uuid: string | null;
  dylibs: string[];
  rpaths: string[];
  segments: MachoSegment[];
  minimumOs: string | null;
  sdk: string | null;
  symbolCount: number;
  exportedSymbols: string[];
  codeSignature: { offset: number; size: number } | null;
  limitations: string[];
}

export function isMacho(buf: Buffer): boolean {
  if (buf.length < 8) return false;
  const magic = buf.readUInt32BE(0);
  return magic === MH_MAGIC || magic === MH_CIGAM || magic === MH_MAGIC_64
    || magic === MH_CIGAM_64 || magic === FAT_MAGIC || magic === FAT_CIGAM || magic === FAT_MAGIC_64;
}

function readCString(buf: Buffer, offset: number): string {
  if (offset < 0 || offset >= buf.length) return '';
  let end = offset;
  while (end < buf.length && buf[end] !== 0) end += 1;
  return buf.toString('utf8', offset, end);
}

/** Parse one Mach-O image (not a fat container). */
function parseThin(buf: Buffer, path: string, base = 0): MachoAnalysis {
  const magicBE = buf.readUInt32BE(base);
  let little: boolean;
  let is64: boolean;

  if (magicBE === MH_MAGIC_64 || magicBE === MH_CIGAM_64) {
    is64 = true;
    little = magicBE === MH_CIGAM_64;
  } else if (magicBE === MH_MAGIC || magicBE === MH_CIGAM) {
    is64 = false;
    little = magicBE === MH_CIGAM;
  } else {
    throw new Error('not a Mach-O image');
  }

  const u16 = (o: number) => (little ? buf.readUInt16LE(o) : buf.readUInt16BE(o));
  const u32 = (o: number) => (little ? buf.readUInt32LE(o) : buf.readUInt32BE(o));
  const i32 = (o: number) => (little ? buf.readInt32LE(o) : buf.readInt32BE(o));
  const u64 = (o: number) => Number(little ? buf.readBigUInt64LE(o) : buf.readBigUInt64BE(o));

  const headerSize = is64 ? 32 : 28;
  const cpuType = i32(base + 4);
  const cpuSubtype = i32(base + 8);
  const fileType = u32(base + 12);
  const ncmds = u32(base + 16);
  const sizeofcmds = u32(base + 20);
  const flags = u32(base + 24);

  const segments: MachoSegment[] = [];
  const dylibs: string[] = [];
  const rpaths: string[] = [];
  const exportedSymbols: string[] = [];
  let uuid: string | null = null;
  let entryPoint: number | null = null;
  let symbolCount = 0;
  let minimumOs: string | null = null;
  let sdk: string | null = null;
  let codeSignature: { offset: number; size: number } | null = null;

  let offset = base + headerSize;
  const commandsEnd = offset + sizeofcmds;

  for (let i = 0; i < ncmds && offset + 8 <= buf.length && offset + 8 <= commandsEnd; i += 1) {
    const cmd = u32(offset);
    const cmdsize = u32(offset + 4);
    if (cmdsize < 8) break;

    if (cmd === LC_SEGMENT_64 || cmd === LC_SEGMENT) {
      const wide = cmd === LC_SEGMENT_64;
      const name = readCString(buf, offset + 8).replace(/\0+$/, '');
      const vmAddress = wide ? u64(offset + 24) : u32(offset + 24);
      const vmSize = wide ? u64(offset + 32) : u32(offset + 28);
      const fileOffset = wide ? u64(offset + 40) : u32(offset + 32);
      const fileSize = wide ? u64(offset + 48) : u32(offset + 36);
      const nsects = u32(offset + (wide ? 64 : 48));
      const sectionStart = offset + (wide ? 72 : 56);
      const sectionSize = wide ? 80 : 68;
      const sections: MachoSection[] = [];
      for (let s = 0; s < nsects; s += 1) {
        const so = sectionStart + s * sectionSize;
        if (so + sectionSize > buf.length) break;
        sections.push({
          name: readCString(buf, so).replace(/\0+$/, ''),
          segment: readCString(buf, so + 16).replace(/\0+$/, ''),
          address: wide ? u64(so + 32) : u32(so + 32),
          size: wide ? u64(so + 40) : u32(so + 36),
          offset: u32(so + (wide ? 48 : 40)),
          flags: describeSectionFlags(u32(so + (wide ? 64 : 56))),
        });
      }
      segments.push({ name, vmAddress, vmSize, fileOffset, fileSize, sections });
    } else if (cmd === LC_LOAD_DYLIB || cmd === LC_ID_DYLIB || cmd === LC_LOAD_WEAK_DYLIB || cmd === LC_REEXPORT_DYLIB) {
      const nameOffset = u32(offset + 8);
      dylibs.push(readCString(buf, offset + nameOffset));
    } else if (cmd === LC_RPATH) {
      const nameOffset = u32(offset + 8);
      rpaths.push(readCString(buf, offset + nameOffset));
    } else if (cmd === LC_UUID) {
      uuid = buf.toString('hex', offset + 8, offset + 24);
    } else if (cmd === LC_MAIN) {
      entryPoint = u64(offset + 8);
    } else if (cmd === LC_SYMTAB) {
      const symoff = u32(offset + 8);
      const nsyms = u32(offset + 12);
      const stroff = u32(offset + 16);
      symbolCount = nsyms;
      const entrySize = is64 ? 16 : 12;
      for (let s = 0; s < nsyms; s += 1) {
        const so = symoff + s * entrySize;
        if (so + entrySize > buf.length) break;
        const strx = u32(so);
        const nType = buf[so + 4];
        const nValue = is64 ? u64(so + 8) : u32(so + 8);
        // N_EXT (0x01) and N_TYPE mask 0x0e; only external symbols are listed.
        const isExternal = (nType & 0x01) !== 0;
        const isUndefined = (nType & 0x0e) === 0x00;
        if (!isExternal || isUndefined || nValue === 0) continue;
        const name = readCString(buf, stroff + strx);
        if (name) exportedSymbols.push(name);
      }
    } else if (cmd === LC_CODE_SIGNATURE) {
      codeSignature = { offset: u32(offset + 8), size: u32(offset + 12) };
    } else if (cmd === LC_BUILD_VERSION) {
      const platform = u32(offset + 8);
      const minos = u32(offset + 12);
      minimumOs = `${PLATFORM_NAMES[platform] ?? platform} ${formatVersion(minos)}`;
      sdk = formatVersion(u32(offset + 16));
    } else if (cmd === LC_VERSION_MIN_MACOSX) {
      minimumOs = `macOS ${formatVersion(u32(offset + 8))}`;
      sdk = formatVersion(u32(offset + 12));
    }

    offset += cmdsize;
  }

  const flagNames: string[] = [];
  if (flags & 0x1) flagNames.push('NOUNDEFS');
  if (flags & 0x4) flagNames.push('DYLDLINK');
  if (flags & 0x80) flagNames.push('TWOLEVEL');
  if (flags & 0x20000) flagNames.push('ALLOW_STACK_EXECUTION');
  if (flags & 0x200000) flagNames.push('PIE');
  if (flags & 0x1000000) flagNames.push('NO_HEAP_EXECUTION');

  const limitations: string[] = [];
  if (symbolCount === 0) limitations.push('The symbol table is empty: this image was stripped.');
  if (codeSignature) limitations.push('The code signature blob was located but not cryptographically verified.');

  return {
    format: 'macho',
    path,
    fileSize: buf.length,
    container: 'thin',
    architectures: [{
      cpu: `${CPU_NAMES[cpuType] ?? `cpu${cpuType}`}${cpuSubtype ? ` (subtype ${cpuSubtype})` : ''}`,
      cpuType,
      fileType: FILETYPE_NAMES[fileType] ?? `filetype${fileType}`,
      offset: base,
      size: buf.length - base,
    }],
    cpu: CPU_NAMES[cpuType] ?? `cpu${cpuType}`,
    fileType: FILETYPE_NAMES[fileType] ?? `filetype${fileType}`,
    bitness: is64 ? 64 : 32,
    byteOrder: little ? 'little' : 'big',
    flags: flagNames,
    entryPoint,
    uuid,
    dylibs,
    rpaths,
    segments,
    minimumOs,
    sdk,
    symbolCount,
    exportedSymbols,
    codeSignature,
    limitations,
  };
}

function formatVersion(value: number): string {
  const major = (value >>> 16) & 0xffff;
  const minor = (value >>> 8) & 0xff;
  const patch = value & 0xff;
  return `${major}.${minor}.${patch}`;
}

function describeSectionFlags(value: number): string {
  const names: string[] = [];
  if (value & 0x1) names.push('PURE_INSTRUCTIONS');
  if (value & 0x2) names.push('NON_LAZY_SYMBOL_POINTERS');
  if (value & 0x80000000) names.push('SOME_INSTRUCTIONS');
  if (value & 0x8000000) names.push('EXTERNAL_RELOC');
  return names.join('|') || '-';
}

/** Parse a Mach-O file, thin or universal. */
export function parseMacho(buf: Buffer, path = '<memory>'): MachoAnalysis {
  if (!isMacho(buf)) throw new Error('not a Mach-O image');

  const magicBE = buf.readUInt32BE(0);
  if (magicBE === FAT_MAGIC || magicBE === FAT_CIGAM || magicBE === FAT_MAGIC_64) {
    const bigEndian = magicBE !== FAT_CIGAM;
    const count = bigEndian ? buf.readUInt32BE(4) : buf.readUInt32LE(4);
    const architectures: MachoAnalysis['architectures'] = [];
    let thin: MachoAnalysis | null = null;

    for (let i = 0; i < count; i += 1) {
      const entry = 8 + i * 20;
      if (entry + 20 > buf.length) break;
      const cpuType = bigEndian ? buf.readInt32BE(entry) : buf.readInt32LE(entry);
      const cpuSubtype = bigEndian ? buf.readInt32BE(entry + 4) : buf.readInt32LE(entry + 4);
      const offset = bigEndian ? buf.readUInt32BE(entry + 8) : buf.readUInt32LE(entry + 8);
      const size = bigEndian ? buf.readUInt32BE(entry + 12) : buf.readUInt32LE(entry + 12);
      architectures.push({
        cpu: `${CPU_NAMES[cpuType] ?? `cpu${cpuType}`}${cpuSubtype ? ` (subtype ${cpuSubtype})` : ''}`,
        cpuType,
        fileType: 'unknown',
        offset,
        size,
      });
      if (!thin) {
        try {
          thin = parseThin(buf, path, offset);
        } catch {
          thin = null;
        }
      }
    }

    if (!thin) throw new Error('the universal binary contains no readable slice');

    const universal: MachoAnalysis = {
      ...thin,
      container: 'universal',
      architectures,
      fileSize: buf.length,
    };
    universal.limitations = [
      ...universal.limitations,
      `This is a universal binary with ${architectures.length} slice(s); the facts below describe the first readable slice (${thin.cpu}).`,
    ];
    return universal;
  }

  return parseThin(buf, path, 0);
}

/** Analyse a Mach-O file on disk and return its Evidence record. */
export async function inspectMacho(path: string): Promise<{ analysis: MachoAnalysis; evidence: Evidence }> {
  const buf = await readFile(path);
  const analysis = parseMacho(buf, path);
  const facts: Fact[] = [];
  const push = (label: string, value: string | number | boolean) => facts.push({ label, value: String(value) });

  push('macho.container', analysis.container);
  push('macho.cpu', analysis.cpu);
  push('macho.bitness', analysis.bitness);
  push('macho.file_type', analysis.fileType);
  push('macho.entry_point', analysis.entryPoint !== null ? `0x${analysis.entryPoint.toString(16)}` : 'none');
  push('macho.uuid', analysis.uuid ?? 'none');
  push('macho.dylibs', analysis.dylibs.join(', ') || 'none');
  push('macho.rpaths', analysis.rpaths.join(', ') || 'none');
  push('macho.segments', analysis.segments.length);
  push('macho.sections', analysis.segments.reduce((sum, s) => sum + s.sections.length, 0));
  push('macho.symbols', analysis.symbolCount);
  push('macho.exported_symbols', analysis.exportedSymbols.length);
  push('macho.minimum_os', analysis.minimumOs ?? 'none');
  push('macho.sdk', analysis.sdk ?? 'none');
  push('macho.flags', analysis.flags.join(', ') || 'none');
  push('macho.code_signature', analysis.codeSignature ? `${analysis.codeSignature.size} bytes` : 'none');

  const evidence = makeEvidence({
    kind: 'macho',
    subject: path,
    summary:
      `${analysis.container === 'universal' ? 'Universal' : 'Thin'} ${analysis.cpu} ${analysis.bitness}-bit ` +
      `${analysis.fileType} with ${analysis.segments.length} segment(s), ${analysis.dylibs.length} dynamic ` +
      `librar${analysis.dylibs.length === 1 ? 'y' : 'ies'} and ${analysis.symbolCount} symbol(s).`,
    facts,
    metrics: [
      { label: 'file.bytes', value: analysis.fileSize },
      { label: 'macho.dylibs', value: analysis.dylibs.length },
      { label: 'macho.symbols', value: analysis.symbolCount },
    ],
    limitations: analysis.limitations,
    data: {
      container: analysis.container,
      cpu: analysis.cpu,
      bitness: analysis.bitness,
      fileType: analysis.fileType,
      uuid: analysis.uuid,
      entryPoint: analysis.entryPoint,
      dylibs: analysis.dylibs,
      rpaths: analysis.rpaths,
      segments: analysis.segments,
      exportedSymbols: analysis.exportedSymbols.slice(0, 500),
      flags: analysis.flags,
      architectures: analysis.architectures,
    },
  });

  return { analysis, evidence };
}
