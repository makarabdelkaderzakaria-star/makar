/**
 * Build a small but genuine PE32+ image in memory, so the PE reader can be
 * tested without a Windows machine and without shipping a binary.
 */
import { Buffer } from 'node:buffer';

export interface PeFixture {
  buffer: Buffer;
  expected: {
    machine: string;
    subsystem: string;
    imports: Record<string, string[]>;
    exports: string[];
    exportName: string;
    aslr: boolean;
    dep: boolean;
    cfg: boolean;
    certificateSize: number;
  };
}

export function buildPe(): PeFixture {
  const DOS_SIZE = 0x80;
  const PE_OFFSET = DOS_SIZE;
  const COFF_OFFSET = PE_OFFSET + 4;
  const OPT_OFFSET = COFF_OFFSET + 20;
  const OPT_SIZE = 240;
  const SECTION_OFFSET = OPT_OFFSET + OPT_SIZE;
  const TEXT_RAW = 0x200;
  const RDATA_RAW = 0x400;
  const CERT_OFFSET = 0x900;
  const TOTAL = 0xa00;

  const buffer = Buffer.alloc(TOTAL);

  // DOS header
  buffer.write('MZ', 0, 'latin1');
  buffer.writeUInt32LE(PE_OFFSET, 0x3c);

  // PE signature
  buffer.write('PE\0\0', PE_OFFSET, 'latin1');

  // COFF header
  buffer.writeUInt16LE(0x8664, COFF_OFFSET);          // Machine: x64
  buffer.writeUInt16LE(2, COFF_OFFSET + 2);           // NumberOfSections
  buffer.writeUInt32LE(0x5f000000, COFF_OFFSET + 4);  // TimeDateStamp
  buffer.writeUInt32LE(0, COFF_OFFSET + 8);           // PointerToSymbolTable
  buffer.writeUInt32LE(0, COFF_OFFSET + 12);          // NumberOfSymbols
  buffer.writeUInt16LE(OPT_SIZE, COFF_OFFSET + 16);   // SizeOfOptionalHeader
  buffer.writeUInt16LE(0x0022, COFF_OFFSET + 18);     // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

  // Optional header (PE32+)
  buffer.writeUInt16LE(0x20b, OPT_OFFSET);            // Magic
  buffer.writeUInt8(14, OPT_OFFSET + 2);              // MajorLinkerVersion
  buffer.writeUInt32LE(0x200, OPT_OFFSET + 4);        // SizeOfCode
  buffer.writeUInt32LE(0x400, OPT_OFFSET + 8);        // SizeOfInitializedData
  buffer.writeUInt32LE(0, OPT_OFFSET + 12);           // SizeOfUninitializedData
  buffer.writeUInt32LE(0x1000, OPT_OFFSET + 16);      // AddressOfEntryPoint
  buffer.writeUInt32LE(0x1000, OPT_OFFSET + 20);      // BaseOfCode
  buffer.writeBigUInt64LE(0x140000000n, OPT_OFFSET + 24); // ImageBase
  buffer.writeUInt32LE(0x1000, OPT_OFFSET + 32);      // SectionAlignment
  buffer.writeUInt32LE(0x200, OPT_OFFSET + 36);       // FileAlignment
  buffer.writeUInt16LE(3, OPT_OFFSET + 68);           // Subsystem: console
  buffer.writeUInt16LE(0x4560, OPT_OFFSET + 70);      // DllCharacteristics
  buffer.writeUInt32LE(0x1000, OPT_OFFSET + 108);     // NumberOfRvaAndSizes

  const dataDirectory = OPT_OFFSET + 112;
  const rvaToFile = (rva: number): number => {
    if (rva >= 0x2000 && rva < 0x2400) return RDATA_RAW + (rva - 0x2000);
    if (rva >= 0x1000 && rva < 0x1200) return TEXT_RAW + (rva - 0x1000);
    return -1;
  };

  // Data directory 0: exports, 1: imports, 4: security (file offset).
  buffer.writeUInt32LE(0x2200, dataDirectory + 0);
  buffer.writeUInt32LE(40, dataDirectory + 4);
  buffer.writeUInt32LE(0x2000, dataDirectory + 8);
  buffer.writeUInt32LE(40, dataDirectory + 12);
  buffer.writeUInt32LE(CERT_OFFSET, dataDirectory + 32);
  buffer.writeUInt32LE(0x30, dataDirectory + 36);

  // Section table
  const writeSection = (index: number, name: string, virtualSize: number, virtualAddress: number, rawSize: number, rawOffset: number, characteristics: number) => {
    const off = SECTION_OFFSET + index * 40;
    buffer.write(name, off, 'latin1');
    buffer.writeUInt32LE(virtualSize, off + 8);
    buffer.writeUInt32LE(virtualAddress, off + 12);
    buffer.writeUInt32LE(rawSize, off + 16);
    buffer.writeUInt32LE(rawOffset, off + 20);
    buffer.writeUInt32LE(characteristics, off + 36);
  };
  writeSection(0, '.text', 0x200, 0x1000, 0x200, TEXT_RAW, 0x60000020);
  writeSection(1, '.rdata', 0x400, 0x2000, 0x400, RDATA_RAW, 0x40000040);

  // .text: a little code
  buffer.writeUInt8(0x48, TEXT_RAW);
  buffer.write('sample payload', TEXT_RAW + 16, 'latin1');

  // .rdata: import descriptor
  const RDATA = RDATA_RAW;
  buffer.writeUInt32LE(0x2040, RDATA + 0);        // OriginalFirstThunk
  buffer.writeUInt32LE(0, RDATA + 4);             // TimeDateStamp
  buffer.writeUInt32LE(0, RDATA + 8);             // ForwarderChain
  buffer.writeUInt32LE(0x2080, RDATA + 12);       // Name
  buffer.writeUInt32LE(0x2100, RDATA + 16);       // FirstThunk
  // terminator at RDATA+20 stays zero

  // Import lookup table
  buffer.writeUInt32LE(0x2090, RDATA + 0x40);
  buffer.writeUInt32LE(0x20a0, RDATA + 0x48);
  buffer.writeBigUInt64LE(0n, RDATA + 0x50);

  // Names
  buffer.write('KERNEL32.dll\0', RDATA + 0x80, 'latin1');
  buffer.writeUInt16LE(0, RDATA + 0x90);
  buffer.write('CreateFileW\0', RDATA + 0x92, 'latin1');
  buffer.writeUInt16LE(0, RDATA + 0xa0);
  buffer.write('CloseHandle\0', RDATA + 0xa2, 'latin1');

  // Import address table
  buffer.writeUInt32LE(0x2090, RDATA + 0x100);
  buffer.writeUInt32LE(0x20a0, RDATA + 0x108);
  buffer.writeBigUInt64LE(0n, RDATA + 0x110);

  // Export directory
  buffer.writeUInt32LE(0x2300, RDATA + 0x20c);     // Name
  buffer.writeUInt32LE(1, RDATA + 0x210);          // Base
  buffer.writeUInt32LE(2, RDATA + 0x214);          // NumberOfFunctions
  buffer.writeUInt32LE(2, RDATA + 0x218);          // NumberOfNames
  buffer.writeUInt32LE(0x2310, RDATA + 0x21c);     // AddressOfFunctions
  buffer.writeUInt32LE(0x2320, RDATA + 0x220);     // AddressOfNames
  buffer.writeUInt32LE(0x2330, RDATA + 0x224);     // AddressOfNameOrdinals

  buffer.write('sample.dll\0', RDATA + 0x300, 'latin1');
  buffer.writeUInt32LE(0x1000, RDATA + 0x310);
  buffer.writeUInt32LE(0x1010, RDATA + 0x314);
  buffer.writeUInt32LE(0x2340, RDATA + 0x320);
  buffer.writeUInt32LE(0x2350, RDATA + 0x324);
  buffer.writeUInt16LE(0, RDATA + 0x330);
  buffer.writeUInt16LE(1, RDATA + 0x332);
  buffer.write('AlphaFunc\0', RDATA + 0x340, 'latin1');
  buffer.write('BetaFunc\0', RDATA + 0x350, 'latin1');

  // Certificate table (file offset, not RVA)
  buffer.writeUInt32LE(0x30, CERT_OFFSET);
  buffer.writeUInt16LE(0x0200, CERT_OFFSET + 4);
  buffer.writeUInt16LE(0x0002, CERT_OFFSET + 6);
  buffer.write('PKCS7', CERT_OFFSET + 8, 'latin1');

  void rvaToFile;

  return {
    buffer,
    expected: {
      machine: 'x86-64',
      subsystem: 'windows console',
      imports: { 'KERNEL32.dll': ['CreateFileW', 'CloseHandle'] },
      exports: ['AlphaFunc', 'BetaFunc'],
      exportName: 'sample.dll',
      aslr: true,
      dep: true,
      cfg: true,
      certificateSize: 0x30,
    },
  };
}
