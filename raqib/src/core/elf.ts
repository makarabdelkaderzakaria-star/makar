/**
 * A self-contained ELF reader (System V / gABI), 32- and 64-bit, both
 * endiannesses. No dependency, no `readelf` on the host.
 *
 * What it proves: header identity, sections, segments, dynamic dependencies,
 * the GNU build-id, exported/imported symbol names, and the hardening flags
 * (PIE, NX, RELRO) that decide whether a binary is safe to run.
 */
import { readFile } from 'node:fs/promises';
import { makeEvidence, type Evidence, type Fact, type SourceLocation } from './evidence.js';

const ELF_MAGIC = 0x7f454c46; // "\x7fELF" little-endian read

const ET_NAMES: Record<number, string> = {
  0: 'ET_NONE', 1: 'ET_REL', 2: 'ET_EXEC', 3: 'ET_DYN', 4: 'ET_CORE',
};

const EM_NAMES: Record<number, string> = {
  0: 'none', 2: 'SPARC', 3: 'x86', 8: 'MIPS', 20: 'PowerPC', 21: 'PowerPC64',
  22: 'S390', 40: 'ARM', 62: 'x86-64', 183: 'AArch64', 243: 'RISC-V',
  258: 'LoongArch',
};

const SHT_NAMES: Record<number, string> = {
  0: 'NULL', 1: 'PROGBITS', 2: 'SYMTAB', 3: 'STRTAB', 4: 'RELA', 5: 'HASH',
  6: 'DYNAMIC', 7: 'NOTE', 8: 'NOBITS', 9: 'REL', 10: 'SHLIB', 11: 'DYNSYM',
  14: 'INIT_ARRAY', 15: 'FINI_ARRAY', 16: 'PREINIT_ARRAY', 17: 'GROUP',
  18: 'SYMTAB_SHNDX',
};

const PT_NAMES: Record<number, string> = {
  0: 'PT_NULL', 1: 'PT_LOAD', 2: 'PT_DYNAMIC', 3: 'PT_INTERP', 4: 'PT_NOTE',
  5: 'PT_SHLIB', 6: 'PT_PHDR', 7: 'PT_TLS',
  0x6474e550: 'PT_GNU_EH_FRAME', 0x6474e551: 'PT_GNU_STACK', 0x6474e552: 'PT_GNU_RELRO',
  0x6474e553: 'PT_GNU_PROPERTY',
};

const DT_NAMES: Record<number, string> = {
  0: 'DT_NULL', 1: 'DT_NEEDED', 2: 'DT_PLTRELSZ', 3: 'DT_PLTGOT', 4: 'DT_HASH',
  5: 'DT_STRTAB', 6: 'DT_SYMTAB', 7: 'DT_RELA', 8: 'DT_RELASZ', 9: 'DT_RELAENT',
  10: 'DT_STRSZ', 11: 'DT_SYMENT', 12: 'DT_INIT', 13: 'DT_FINI', 14: 'DT_SONAME',
  15: 'DT_RPATH', 16: 'DT_SYMBOLIC', 17: 'DT_REL', 20: 'DT_PLTREL', 21: 'DT_DEBUG',
  23: 'DT_JMPREL', 24: 'DT_BIND_NOW', 25: 'DT_INIT_ARRAY', 26: 'DT_FINI_ARRAY',
  27: 'DT_INIT_ARRAYSZ', 28: 'DT_FINI_ARRAYSZ', 30: 'DT_FLAGS', 32: 'DT_RELACOUNT',
  0x6ffffef5: 'DT_GNU_HASH', 0x6ffffff0: 'DT_VERSYM', 0x6ffffffc: 'DT_VERDEF',
  0x6ffffffe: 'DT_VERNEED', 0x6fffffff: 'DT_VERNEEDNUM',
  0x6ffffffb: 'DT_FLAGS_1',
};

const DF_1_PIE = 0x08000000;

export interface ElfSection {
  index: number;
  name: string;
  type: string;
  flags: string;
  address: number;
  offset: number;
  size: number;
  link: number;
  entsize: number;
}

export interface ElfSegment {
  type: string;
  flags: number;
  offset: number;
  vaddr: number;
  filesz: number;
  memsz: number;
  align: number;
}

export interface ElfSymbol {
  name: string;
  value: number;
  size: number;
  info: number;
  shndx: number;
  bind: string;
  type: string;
  defined: boolean;
}

export interface ElfAnalysis {
  format: 'elf';
  path: string;
  fileSize: number;
  class: 'ELF32' | 'ELF64';
  endian: 'little' | 'big';
  osabi: string;
  type: string;
  machine: string;
  entry: number;
  interpreter: string | null;
  sections: ElfSection[];
  segments: ElfSegment[];
  needed: string[];
  soname: string | null;
  buildId: string | null;
  runpath: string[];
  symbols: ElfSymbol[];
  exportedSymbols: string[];
  importedSymbols: string[];
  hardening: {
    pie: boolean;
    nx: boolean;
    relro: boolean;
    stripped: boolean;
    fortify: boolean;
  };
  limitations: string[];
}

const BIND_NAMES = ['LOCAL', 'GLOBAL', 'WEAK'];
const STT_NAMES = ['NOTYPE', 'OBJECT', 'FUNC', 'SECTION', 'FILE', 'COMMON', 'TLS', 'IFUNC'];

function cstr(buf: Buffer, offset: number): string {
  if (offset < 0 || offset >= buf.length) return '';
  let end = offset;
  while (end < buf.length && buf[end] !== 0) end += 1;
  return buf.toString('utf8', offset, end);
}

export function isElf(buf: Buffer): boolean {
  return buf.length > 4 && buf.readUInt32BE(0) === ELF_MAGIC;
}

/** Parse an ELF image held in memory. */
export function parseElf(buf: Buffer, path = '<memory>'): ElfAnalysis {
  if (!isElf(buf)) throw new Error('not an ELF image (bad magic)');
  if (buf.length < 16) throw new Error('truncated ELF identification');

  const eiClass = buf[4];
  const eiData = buf[5];
  const eiVersion = buf[6];
  const eiOsabi = buf[7];

  if (eiClass !== 1 && eiClass !== 2) throw new Error(`unknown ELF class ${eiClass}`);
  if (eiData !== 1 && eiData !== 2) throw new Error(`unknown ELF data encoding ${eiData}`);

  const is64 = eiClass === 2;
  const le = eiData === 1;
  const u16 = (o: number) => (le ? buf.readUInt16LE(o) : buf.readUInt16BE(o));
  const u32 = (o: number) => (le ? buf.readUInt32LE(o) : buf.readUInt32BE(o));
  const u64 = (o: number) => (le ? buf.readBigUInt64LE(o) : buf.readBigUInt64BE(o));
  const addr = (o: number) => (is64 ? Number(u64(o)) : u32(o));

  if (buf.length < (is64 ? 64 : 52)) throw new Error('truncated ELF header');

  const eType = u16(16);
  const eMachine = u16(18);
  const eVersion = u32(20);
  const eEntry = addr(is64 ? 24 : 24);
  const ePhoff = is64 ? Number(u64(32)) : u32(28);
  const eShoff = is64 ? Number(u64(40)) : u32(32);
  const eFlags = u32(is64 ? 48 : 36);
  const eEhsize = u16(is64 ? 52 : 40);
  const ePhentsize = u16(is64 ? 54 : 42);
  const ePhnum = u16(is64 ? 56 : 44);
  const eShentsize = u16(is64 ? 58 : 46);
  const eShnum = u16(is64 ? 60 : 48);
  const eShstrndx = u16(is64 ? 62 : 50);

  const sections: ElfSection[] = [];
  const rawSections: Array<{ nameOffset: number; type: number; flags: number; address: number; offset: number; size: number; link: number; entsize: number }> = [];

  for (let i = 0; i < eShnum; i += 1) {
    const off = eShoff + i * eShentsize;
    if (off + eShentsize > buf.length) break;
    const nameOffset = u32(off);
    const type = u32(off + 4);
    const flags = is64 ? Number(u64(off + 8)) : u32(off + 8);
    const address = addr(off + (is64 ? 16 : 12));
    const offset = is64 ? Number(u64(off + 24)) : u32(off + 16);
    const size = is64 ? Number(u64(off + 32)) : u32(off + 20);
    const link = u32(off + (is64 ? 40 : 24));
    const entsize = is64 ? Number(u64(off + 56)) : u32(off + 36);
    rawSections.push({ nameOffset, type, flags, address, offset, size, link, entsize });
  }

  const shstr = rawSections[eShstrndx];
  const sectionName = (nameOffset: number): string => {
    if (!shstr) return '';
    return cstr(buf, shstr.offset + nameOffset);
  };

  rawSections.forEach((s, index) => {
    sections.push({
      index,
      name: sectionName(s.nameOffset),
      type: SHT_NAMES[s.type] ?? `0x${s.type.toString(16)}`,
      flags: describeSectionFlags(s.flags),
      address: s.address,
      offset: s.offset,
      size: s.size,
      link: s.link,
      entsize: s.entsize,
    });
  });

  const segments: ElfSegment[] = [];
  for (let i = 0; i < ePhnum; i += 1) {
    const off = ePhoff + i * ePhentsize;
    if (off + ePhentsize > buf.length) break;
    const type = u32(off);
    const flags = is64 ? u32(off + 4) : u32(off + 24);
    const offset = is64 ? Number(u64(off + 8)) : u32(off + 4);
    const vaddr = addr(off + (is64 ? 16 : 8));
    const filesz = is64 ? Number(u64(off + 32)) : u32(off + 16);
    const memsz = is64 ? Number(u64(off + 40)) : u32(off + 20);
    const align = is64 ? Number(u64(off + 48)) : u32(off + 28);
    segments.push({ type: PT_NAMES[type] ?? `0x${type.toString(16)}`, flags, offset, vaddr, filesz, memsz, align });
  }

  let interpreter: string | null = null;
  let needed: string[] = [];
  let soname: string | null = null;
  let runpath: string[] = [];
  let buildId: string | null = null;
  let dynamicFlags = 0;
  let dynamicFlags1 = 0;

  // Translate a virtual address into a file offset using the PT_LOAD segments.
  const vaddrToOffset = (vaddr: number): number => {
    for (const seg of segments) {
      if (seg.type !== 'PT_LOAD') continue;
      if (vaddr >= seg.vaddr && vaddr < seg.vaddr + seg.filesz) {
        return seg.offset + (vaddr - seg.vaddr);
      }
    }
    return -1;
  };

  const dynamicSegment = segments.find((s) => s.type === 'PT_DYNAMIC');
  const dynamicSection = sections.find((s) => s.type === 'DYNAMIC');
  const dynamicOffset = dynamicSegment?.offset ?? dynamicSection?.offset;
  const dynamicSize = dynamicSegment?.filesz ?? dynamicSection?.size ?? 0;

  if (dynamicOffset !== undefined && dynamicSize > 0) {
    const entrySize = is64 ? 16 : 8;
    let strtabOffset = -1;
    const rawDynamic: Array<{ tag: number; value: number }> = [];
    for (let off = dynamicOffset; off + entrySize <= buf.length && off < dynamicOffset + dynamicSize; off += entrySize) {
      const tag = is64 ? Number(u64(off)) : u32(off);
      const value = is64 ? Number(u64(off + 8)) : u32(off + 4);
      if (tag === 0) break;
      rawDynamic.push({ tag, value });
      if (tag === 5) strtabOffset = vaddrToOffset(value);
    }
    for (const { tag, value } of rawDynamic) {
      if (tag === 1) { const s = readStringAt(buf, strtabOffset, value); if (s) needed.push(s); }
      else if (tag === 14) soname = readStringAt(buf, strtabOffset, value) ?? null;
      else if (tag === 15 || tag === 29) { const s = readStringAt(buf, strtabOffset, value); if (s) runpath.push(s); }
      else if (tag === 30) dynamicFlags = value;
      else if (tag === 0x6ffffffb) dynamicFlags1 = value;
    }
  }

  // The build id lives in its own note section, which is not necessarily the
  // first NOTE section: scan them all.
  const noteSections = sections.filter((s) => s.type === 'NOTE');
  for (const noteSection of noteSections) {
    const id = readBuildId(buf, noteSection);
    if (id) { buildId = id; break; }
  }

  const interpSegment = segments.find((s) => s.type === 'PT_INTERP');
  if (interpSegment) {
    interpreter = cstr(buf, interpSegment.offset) || null;
  }

  const symbols = readSymbols(buf, sections, is64, le);
  const exportedSymbols = symbols
    .filter((s) => s.defined && s.type === 'FUNC' && s.bind !== 'LOCAL')
    .map((s) => s.name)
    .filter(Boolean);
  const importedSymbols = symbols
    .filter((s) => !s.defined && s.name)
    .map((s) => s.name);

  const pie = eType === 3 && ((dynamicFlags1 & DF_1_PIE) !== 0 || dynamicSection !== undefined);
  const nx = segments.some((s) => s.type === 'PT_GNU_STACK' && (s.flags & 0x1) === 0);
  const relro = segments.some((s) => s.type === 'PT_GNU_RELRO');
  const stripped = !sections.some((s) => s.type === 'SYMTAB');
  const fortify = symbols.some((s) => s.name.includes('__fortify'));

  return {
    format: 'elf',
    path,
    fileSize: buf.length,
    class: is64 ? 'ELF64' : 'ELF32',
    endian: le ? 'little' : 'big',
    osabi: osabiName(eiOsabi),
    type: ET_NAMES[eType] ?? `0x${eType.toString(16)}`,
    machine: EM_NAMES[eMachine] ?? `0x${eMachine.toString(16)}`,
    entry: eEntry,
    interpreter,
    sections,
    segments,
    needed,
    soname,
    buildId,
    runpath,
    symbols,
    exportedSymbols,
    importedSymbols,
    hardening: { pie, nx, relro, stripped, fortify },
    limitations: buildLimitations(buf, sections, symbols),
  };
}

function osabiName(value: number): string {
  switch (value) {
    case 0: return 'UNIX - System V';
    case 3: return 'UNIX - GNU';
    case 9: return 'UNIX - FreeBSD';
    default: return `0x${value.toString(16)}`;
  }
}

function describeSectionFlags(flags: number): string {
  const names: string[] = [];
  if (flags & 0x1) names.push('WRITE');
  if (flags & 0x2) names.push('ALLOC');
  if (flags & 0x4) names.push('EXECINSTR');
  if (flags & 0x10) names.push('MERGE');
  if (flags & 0x20) names.push('STRINGS');
  if (flags & 0x400) names.push('INFO_LINK');
  if (flags & 0x800) names.push('LINK_ORDER');
  if (flags & 0x80000000) names.push('EXCLUDE');
  return names.join('|') || '-';
}

/** Read a NUL-terminated string at a base offset plus an index. */
function readStringAt(buf: Buffer, base: number, index: number): string | null {
  if (base < 0) return null;
  const value = cstr(buf, base + index);
  return value.length ? value : null;
}

function readSymbols(buf: Buffer, sections: ElfSection[], is64: boolean, le: boolean): ElfSymbol[] {
  const out: ElfSymbol[] = [];
  const u16 = (o: number) => (le ? buf.readUInt16LE(o) : buf.readUInt16BE(o));
  const u32 = (o: number) => (le ? buf.readUInt32LE(o) : buf.readUInt32BE(o));
  const u64 = (o: number) => Number(le ? buf.readBigUInt64LE(o) : buf.readBigUInt64BE(o));

  for (const section of sections) {
    if (section.type !== 'SYMTAB' && section.type !== 'DYNSYM') continue;
    const strtab = sections[section.link];
    if (!strtab) continue;
    const entsize = section.entsize || (is64 ? 24 : 16);
    if (entsize <= 0) continue;
    for (let off = section.offset; off + entsize <= buf.length && off < section.offset + section.size; off += entsize) {
      let nameOffset: number;
      let value: number;
      let size: number;
      let info: number;
      let shndx: number;
      if (is64) {
        nameOffset = u32(off);
        info = buf[off + 4];
        shndx = u16(off + 6);
        value = u64(off + 8);
        size = u64(off + 16);
      } else {
        nameOffset = u32(off);
        value = u32(off + 4);
        size = u32(off + 8);
        info = buf[off + 12];
        shndx = u16(off + 14);
      }
      const name = cstr(buf, strtab.offset + nameOffset);
      const bind = BIND_NAMES[info >> 4] ?? `bind${info >> 4}`;
      const type = STT_NAMES[info & 0xf] ?? `type${info & 0xf}`;
      out.push({ name, value, size, info, shndx, bind, type, defined: shndx !== 0 });
    }
  }
  return out;
}

function readBuildId(buf: Buffer, section: ElfSection): string | null {
  let off = section.offset;
  const end = section.offset + section.size;
  while (off + 12 <= end && off + 12 <= buf.length) {
    const namesz = buf.readUInt32LE(off);
    const descsz = buf.readUInt32LE(off + 4);
    const type = buf.readUInt32LE(off + 8);
    const nameStart = off + 12;
    const descStart = nameStart + ((namesz + 3) & ~3);
    const descEnd = descStart + descsz;
    if (descEnd > buf.length) return null;
    const name = buf.toString('utf8', nameStart, nameStart + Math.max(0, namesz - 1));
    // NT_GNU_BUILD_ID is note type 3 in the GNU namespace.
    if (name.startsWith('GNU') && type === 3) {
      return buf.toString('hex', descStart, descEnd);
    }
    off = descStart + ((descsz + 3) & ~3);
  }
  return null;
}

function buildLimitations(buf: Buffer, sections: ElfSection[], symbols: ElfSymbol[]): string[] {
  const limitations: string[] = [];
  if (!sections.some((s) => s.type === 'SYMTAB')) {
    limitations.push('The symbol table was stripped: only dynamic symbols remain, so internal function names cannot be recovered.');
  }
  if (!symbols.length) {
    limitations.push('No symbol table was readable; names below come from strings, not from the linker symbol table.');
  }
  if (buf.length > 512 * 1024 * 1024) {
    limitations.push('The image is larger than 512 MiB; section reads were not verified against the whole file.');
  }
  return limitations;
}

/** Analyse an ELF file on disk and return its Evidence record. */
export async function inspectElf(path: string): Promise<{ analysis: ElfAnalysis; evidence: Evidence }> {
  const buf = await readFile(path);
  const analysis = parseElf(buf, path);
  const facts: Fact[] = [];
  const locations: SourceLocation[] = [];

  const push = (label: string, value: string | number | boolean, source?: SourceLocation) => {
    facts.push({ label, value: String(value), source });
  };

  push('elf.class', analysis.class);
  push('elf.endianness', analysis.endian);
  push('elf.type', analysis.type);
  push('elf.machine', analysis.machine);
  push('elf.osabi', analysis.osabi);
  push('elf.entry_point', `0x${analysis.entry.toString(16)}`);
  push('elf.interpreter', analysis.interpreter ?? 'none');
  push('elf.sections', analysis.sections.length);
  push('elf.segments', analysis.segments.length);
  push('elf.needed', analysis.needed.join(', ') || 'none');
  push('elf.soname', analysis.soname ?? 'none');
  push('elf.runpath', analysis.runpath.join(', ') || 'none');
  push('elf.build_id', analysis.buildId ?? 'none');
  push('elf.symbols', analysis.symbols.length);
  push('elf.exported_functions', analysis.exportedSymbols.length);
  push('elf.imported_symbols', analysis.importedSymbols.length);
  push('hardening.pie', analysis.hardening.pie);
  push('hardening.nx', analysis.hardening.nx);
  push('hardening.relro', analysis.hardening.relro);
  push('hardening.stripped', analysis.hardening.stripped);

  const evidence = makeEvidence({
    kind: 'elf',
    subject: path,
    summary:
      `${analysis.class} ${analysis.machine} ${analysis.type} image with ${analysis.sections.length} sections, ` +
      `${analysis.needed.length} shared libraries and ${analysis.exportedSymbols.length} exported functions. ` +
      `Hardening: ${analysis.hardening.pie ? 'PIE' : 'no PIE'}, ${analysis.hardening.nx ? 'NX' : 'NX missing'}, ` +
      `${analysis.hardening.relro ? 'RELRO' : 'no RELRO'}.`,
    facts,
    locations,
    metrics: [
      { label: 'file.bytes', value: analysis.fileSize },
      { label: 'elf.sections', value: analysis.sections.length },
      { label: 'elf.symbols', value: analysis.symbols.length },
    ],
    limitations: analysis.limitations,
    data: {
      class: analysis.class,
      machine: analysis.machine,
      type: analysis.type,
      interpreter: analysis.interpreter,
      needed: analysis.needed,
      soname: analysis.soname,
      buildId: analysis.buildId,
      sections: analysis.sections.map((s) => ({ name: s.name, type: s.type, size: s.size, address: s.address })),
      segments: analysis.segments.map((s) => ({ type: s.type, flags: s.flags, vaddr: s.vaddr, memsz: s.memsz })),
      exportedSymbols: analysis.exportedSymbols.slice(0, 500),
      importedSymbols: analysis.importedSymbols.slice(0, 500),
      hardening: analysis.hardening,
    },
  });

  return { analysis, evidence };
}
