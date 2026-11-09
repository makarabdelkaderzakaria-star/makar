/**
 * A self-contained PE / COFF reader for Windows binaries.
 *
 * What it proves: machine, subsystem, sections, imported and exported
 * symbols, the Authenticode certificate table, and the DllCharacteristics
 * bits that express ASLR, DEP, CFG and high-entropy ASLR.
 */
import { readFile } from 'node:fs/promises';
import { makeEvidence, type Evidence, type Fact } from './evidence.js';

const MACHINE_NAMES: Record<number, string> = {
  0x014c: 'i386', 0x0166: 'MIPS R4000', 0x01a2: 'Hitachi SH3', 0x01c0: 'ARM',
  0x01c4: 'ARM NT', 0x01f0: 'PowerPC', 0x0200: 'IA64', 0x0266: 'MIPS16',
  0x0366: 'MIPS FPU', 0x8664: 'x86-64', 0xaa64: 'ARM64',
};

const SUBSYSTEM_NAMES: Record<number, string> = {
  0: 'unknown', 1: 'native', 2: 'windows GUI', 3: 'windows console',
  5: 'OS/2 console', 7: 'POSIX console', 9: 'Windows CE GUI',
  10: 'EFI application', 11: 'EFI boot service driver', 12: 'EFI runtime driver',
  13: 'EFI ROM', 14: 'XBOX', 16: 'Windows boot application',
};

const DATA_DIRECTORY_NAMES = [
  'export', 'import', 'resource', 'exception', 'security', 'basereloc',
  'debug', 'architecture', 'globalptr', 'tls', 'load_config', 'bound_import',
  'iat', 'delay_import', 'clr', 'reserved',
];

export interface PeSection {
  name: string;
  virtualSize: number;
  virtualAddress: number;
  rawSize: number;
  rawOffset: number;
  characteristics: string;
}

export interface PeImport {
  dll: string;
  functions: string[];
}

export interface PeExport {
  name: string | null;
  functions: string[];
}

export interface PeAnalysis {
  format: 'pe';
  path: string;
  fileSize: number;
  machine: string;
  machineValue: number;
  subsystem: string;
  characteristics: string[];
  isDll: boolean;
  isDriver: boolean;
  timestamp: number;
  entryPoint: number;
  imageBase: number;
  sections: PeSection[];
  imports: PeImport[];
  exports: PeExport;
  certificate: { size: number; revision: string; type: string } | null;
  dataDirectories: Array<{ name: string; rva: number; size: number }>;
  hardening: {
    aslr: boolean;
    highEntropyAslr: boolean;
    dep: boolean;
    cfg: boolean;
    noSeh: boolean;
    forceIntegrity: boolean;
    relocsStripped: boolean;
  };
  limitations: string[];
}

const CHARACTERISTIC_FLAGS: Array<[number, string]> = [
  [0x0001, 'RELOCS_STRIPPED'], [0x0002, 'EXECUTABLE_IMAGE'], [0x0004, 'LINE_NUMS_STRIPPED'],
  [0x0008, 'LOCAL_SYMS_STRIPPED'], [0x0020, 'LARGE_ADDRESS_AWARE'], [0x0100, '32BIT_MACHINE'],
  [0x0200, 'DEBUG_STRIPPED'], [0x2000, 'DLL'],
];

const DLL_CHARACTERISTIC_FLAGS: Array<[number, string]> = [
  [0x0020, 'HIGH_ENTROPY_VA'], [0x0040, 'DYNAMIC_BASE'], [0x0080, 'FORCE_INTEGRITY'],
  [0x0100, 'NX_COMPAT'], [0x0200, 'NO_ISOLATION'], [0x0400, 'NO_SEH'],
  [0x0800, 'NO_BIND'], [0x1000, 'APPCONTAINER'], [0x2000, 'WDM_DRIVER'],
  [0x4000, 'GUARD_CF'], [0x8000, 'TERMINAL_SERVER_AWARE'],
];

export function isPe(buf: Buffer): boolean {
  return buf.length > 0x40 && buf[0] === 0x4d && buf[1] === 0x5a; // "MZ"
}

function rvaToOffset(rva: number, sections: Array<{ virtualAddress: number; virtualSize: number; rawOffset: number; rawSize: number }>): number {
  for (const section of sections) {
    const size = Math.max(section.virtualSize, section.rawSize);
    if (rva >= section.virtualAddress && rva < section.virtualAddress + size) {
      return section.rawOffset + (rva - section.virtualAddress);
    }
  }
  return -1;
}

function readCString(buf: Buffer, offset: number): string {
  if (offset < 0 || offset >= buf.length) return '';
  let end = offset;
  while (end < buf.length && buf[end] !== 0) end += 1;
  return buf.toString('utf8', offset, end);
}

/** Parse a PE image held in memory. */
export function parsePe(buf: Buffer, path = '<memory>'): PeAnalysis {
  if (!isPe(buf)) throw new Error('not a PE image (missing MZ signature)');
  const lfanew = buf.readUInt32LE(0x3c);
  if (lfanew + 24 > buf.length) throw new Error('truncated PE header');
  if (buf.readUInt32LE(lfanew) !== 0x00004550) throw new Error('missing PE signature');

  const coff = lfanew + 4;
  const machine = buf.readUInt16LE(coff);
  const numberOfSections = buf.readUInt16LE(coff + 2);
  const timestamp = buf.readUInt32LE(coff + 4);
  const sizeOfOptionalHeader = buf.readUInt16LE(coff + 16);
  const characteristics = buf.readUInt16LE(coff + 18);

  const opt = coff + 20;
  if (opt + 2 > buf.length) throw new Error('truncated optional header');
  const magic = buf.readUInt16LE(opt);
  const isPe32Plus = magic === 0x20b;
  if (magic !== 0x10b && magic !== 0x20b) throw new Error(`unknown optional header magic 0x${magic.toString(16)}`);

  const entryPoint = buf.readUInt32LE(opt + 16);
  const imageBase = isPe32Plus
    ? Number(buf.readBigUInt64LE(opt + 24))
    : buf.readUInt32LE(opt + 28);
  const subsystem = buf.readUInt16LE(opt + (isPe32Plus ? 68 : 68));
  const dllCharacteristics = buf.readUInt16LE(opt + 70);
  const numberOfRvaAndSizes = buf.readUInt32LE(opt + (isPe32Plus ? 108 : 92));
  const dataDirectoryOffset = opt + (isPe32Plus ? 112 : 96);

  const sectionTable = opt + sizeOfOptionalHeader;
  const sections: PeSection[] = [];
  for (let i = 0; i < numberOfSections; i += 1) {
    const off = sectionTable + i * 40;
    if (off + 40 > buf.length) break;
    const rawName = buf.toString('latin1', off, off + 8).replace(/\0+$/, '');
    sections.push({
      name: rawName,
      virtualSize: buf.readUInt32LE(off + 8),
      virtualAddress: buf.readUInt32LE(off + 12),
      rawSize: buf.readUInt32LE(off + 16),
      rawOffset: buf.readUInt32LE(off + 20),
      characteristics: describeSectionCharacteristics(buf.readUInt32LE(off + 36)),
    });
  }

  const dataDirectories: PeAnalysis['dataDirectories'] = [];
  for (let i = 0; i < Math.min(numberOfRvaAndSizes, 16); i += 1) {
    const off = dataDirectoryOffset + i * 8;
    if (off + 8 > buf.length) break;
    dataDirectories.push({
      name: DATA_DIRECTORY_NAMES[i] ?? `dir${i}`,
      rva: buf.readUInt32LE(off),
      size: buf.readUInt32LE(off + 4),
    });
  }

  const importDir = dataDirectories[1];
  const imports: PeImport[] = [];
  if (importDir && importDir.rva > 0) {
    const importOffset = rvaToOffset(importDir.rva, sections);
    if (importOffset > 0) {
      for (let i = 0; i < 4096; i += 1) {
        const desc = importOffset + i * 20;
        if (desc + 20 > buf.length) break;
        const originalFirstThunk = buf.readUInt32LE(desc);
        const nameRva = buf.readUInt32LE(desc + 12);
        const firstThunk = buf.readUInt32LE(desc + 16);
        if (originalFirstThunk === 0 && nameRva === 0 && firstThunk === 0) break;
        const dll = readCString(buf, rvaToOffset(nameRva, sections));
        const functions: string[] = [];
        const thunkRva = originalFirstThunk || firstThunk;
        const thunkOffset = thunkRva ? rvaToOffset(thunkRva, sections) : -1;
        if (thunkOffset > 0) {
          const width = isPe32Plus ? 8 : 4;
          for (let t = 0; t < 8192; t += 1) {
            const entry = thunkOffset + t * width;
            if (entry + width > buf.length) break;
            const value = isPe32Plus
              ? buf.readBigUInt64LE(entry)
              : BigInt(buf.readUInt32LE(entry));
            if (value === 0n) break;
            const ordinalFlag = isPe32Plus ? 0x8000_0000_0000_0000n : 0x8000_0000n;
            if ((value & ordinalFlag) !== 0n) {
              functions.push(`#${value & 0xffffn}`);
            } else {
              const hintNameOffset = rvaToOffset(Number(value), sections);
              if (hintNameOffset >= 0) {
                functions.push(readCString(buf, hintNameOffset + 2));
              }
            }
          }
        }
        imports.push({ dll, functions });
      }
    }
  }

  const exportDir = dataDirectories[0];
  const exportInfo: PeExport = { name: null, functions: [] };
  if (exportDir && exportDir.rva > 0) {
    const off = rvaToOffset(exportDir.rva, sections);
    if (off > 0 && off + 40 <= buf.length) {
      const nameRva = buf.readUInt32LE(off + 12);
      const numberOfFunctions = buf.readUInt32LE(off + 20);
      const numberOfNames = buf.readUInt32LE(off + 24);
      const addressOfFunctions = buf.readUInt32LE(off + 28);
      const addressOfNames = buf.readUInt32LE(off + 32);
      const addressOfNameOrdinals = buf.readUInt32LE(off + 36);
      exportInfo.name = readCString(buf, rvaToOffset(nameRva, sections)) || null;
      const functionsOffset = rvaToOffset(addressOfFunctions, sections);
      const namesOffset = rvaToOffset(addressOfNames, sections);
      const ordinalsOffset = rvaToOffset(addressOfNameOrdinals, sections);
      for (let i = 0; i < numberOfNames; i += 1) {
        if (!namesOffset || !ordinalsOffset) break;
        const namePtrOff = namesOffset + i * 4;
        if (namePtrOff + 4 > buf.length) break;
        const namePtr = buf.readUInt32LE(namePtrOff);
        const ordinal = buf.readUInt16LE(ordinalsOffset + i * 2);
        if (!functionsOffset) break;
        const fnOff = functionsOffset + ordinal * 4;
        if (fnOff + 4 > buf.length) continue;
        const fnRva = buf.readUInt32LE(fnOff);
        if (fnRva === 0) continue; // forwarder / hole
        exportInfo.functions.push(readCString(buf, rvaToOffset(namePtr, sections)));
      }
      void numberOfFunctions;
    }
  }

  // The security directory uses a file offset, not an RVA.
  const securityDir = dataDirectories[4];
  let certificate: PeAnalysis['certificate'] = null;
  if (securityDir && securityDir.rva > 0 && securityDir.rva + 8 <= buf.length) {
    const len = buf.readUInt32LE(securityDir.rva);
    const revision = buf.readUInt16LE(securityDir.rva + 4);
    const type = buf.readUInt16LE(securityDir.rva + 6);
    certificate = {
      size: len,
      revision: revision === 0x0200 ? 'WIN_CERT_REVISION_2_0' : `0x${revision.toString(16)}`,
      type: certificateTypeName(type),
    };
  }

  const characteristicNames = CHARACTERISTIC_FLAGS
    .filter(([bit]) => (characteristics & bit) !== 0)
    .map(([, name]) => name);

  return {
    format: 'pe',
    path,
    fileSize: buf.length,
    machine: MACHINE_NAMES[machine] ?? `0x${machine.toString(16)}`,
    machineValue: machine,
    subsystem: SUBSYSTEM_NAMES[subsystem] ?? `0x${subsystem.toString(16)}`,
    characteristics: characteristicNames,
    isDll: (characteristics & 0x2000) !== 0,
    isDriver: (dllCharacteristics & 0x2000) !== 0,
    timestamp,
    entryPoint,
    imageBase,
    sections,
    imports,
    exports: exportInfo,
    certificate,
    dataDirectories,
    hardening: {
      aslr: (dllCharacteristics & 0x0040) !== 0,
      highEntropyAslr: (dllCharacteristics & 0x0020) !== 0,
      dep: (dllCharacteristics & 0x0100) !== 0,
      cfg: (dllCharacteristics & 0x4000) !== 0,
      noSeh: (dllCharacteristics & 0x0400) !== 0,
      forceIntegrity: (dllCharacteristics & 0x0080) !== 0,
      relocsStripped: (characteristics & 0x0001) !== 0,
    },
    limitations: buildLimitations(imports, exportInfo, certificate),
  };
}

function certificateTypeName(type: number): string {
  switch (type) {
    case 0x0001: return 'WIN_CERT_TYPE_X509';
    case 0x0002: return 'WIN_CERT_TYPE_PKCS_SIGNED_DATA';
    case 0x0003: return 'WIN_CERT_TYPE_RESERVED_1';
    case 0x0004: return 'WIN_CERT_TYPE_TS_STACK_SIGNED';
    default: return `0x${type.toString(16)}`;
  }
}

function describeSectionCharacteristics(value: number): string {
  const names: string[] = [];
  if (value & 0x0000_0020) names.push('CODE');
  if (value & 0x0000_0040) names.push('INITIALIZED_DATA');
  if (value & 0x0000_0080) names.push('UNINITIALIZED_DATA');
  if (value & 0x0200_0000) names.push('DISCARDABLE');
  if (value & 0x1000_0000) names.push('SHARED');
  if (value & 0x2000_0000) names.push('EXECUTE');
  if (value & 0x4000_0000) names.push('READ');
  if (value & 0x8000_0000) names.push('WRITE');
  return names.join('|') || '-';
}

function buildLimitations(imports: PeImport[], exports: PeExport, certificate: PeAnalysis['certificate']): string[] {
  const limitations: string[] = [];
  if (!imports.length) limitations.push('No import table was found; the image may be packed or statically linked.');
  if (!exports.functions.length) limitations.push('No export table was found.');
  if (certificate) {
    limitations.push('The Authenticode blob was located but its PKCS#7 signature was not cryptographically verified.');
  }
  void exports;
  return limitations;
}

/** Analyse a PE file on disk and return its Evidence record. */
export async function inspectPe(path: string): Promise<{ analysis: PeAnalysis; evidence: Evidence }> {
  const buf = await readFile(path);
  const analysis = parsePe(buf, path);
  const facts: Fact[] = [];
  const push = (label: string, value: string | number | boolean) => facts.push({ label, value: String(value) });

  push('pe.machine', analysis.machine);
  push('pe.subsystem', analysis.subsystem);
  push('pe.is_dll', analysis.isDll);
  push('pe.is_driver', analysis.isDriver);
  push('pe.entry_point', `0x${analysis.entryPoint.toString(16)}`);
  push('pe.image_base', `0x${analysis.imageBase.toString(16)}`);
  push('pe.sections', analysis.sections.length);
  push('pe.import_dlls', analysis.imports.length);
  push('pe.imported_functions', analysis.imports.reduce((sum, i) => sum + i.functions.length, 0));
  push('pe.exported_functions', analysis.exports.functions.length);
  push('pe.export_name', analysis.exports.name ?? 'none');
  push('pe.certificate', analysis.certificate ? `${analysis.certificate.type} (${analysis.certificate.size} bytes)` : 'none');
  push('pe.timestamp', new Date(analysis.timestamp * 1000).toISOString());
  push('hardening.aslr', analysis.hardening.aslr);
  push('hardening.high_entropy_aslr', analysis.hardening.highEntropyAslr);
  push('hardening.dep', analysis.hardening.dep);
  push('hardening.cfg', analysis.hardening.cfg);
  push('hardening.force_integrity', analysis.hardening.forceIntegrity);

  const evidence = makeEvidence({
    kind: 'pe',
    subject: path,
    summary:
      `${analysis.machine} ${analysis.isDll ? 'DLL' : 'executable'} for the ${analysis.subsystem} subsystem, ` +
      `${analysis.imports.length} imported libraries, ${analysis.exports.functions.length} exports, ` +
      `${analysis.certificate ? 'an Authenticode certificate' : 'no Authenticode certificate'}. ` +
      `Hardening: ${analysis.hardening.aslr ? 'ASLR' : 'no ASLR'}, ${analysis.hardening.dep ? 'DEP' : 'no DEP'}, ` +
      `${analysis.hardening.cfg ? 'CFG' : 'no CFG'}.`,
    facts,
    metrics: [
      { label: 'file.bytes', value: analysis.fileSize },
      { label: 'pe.sections', value: analysis.sections.length },
      { label: 'pe.imports', value: analysis.imports.reduce((sum, i) => sum + i.functions.length, 0) },
    ],
    limitations: analysis.limitations,
    data: {
      machine: analysis.machine,
      subsystem: analysis.subsystem,
      isDll: analysis.isDll,
      timestamp: analysis.timestamp,
      sections: analysis.sections,
      imports: analysis.imports,
      exports: analysis.exports,
      certificate: analysis.certificate,
      hardening: analysis.hardening,
    },
  });

  return { analysis, evidence };
}
