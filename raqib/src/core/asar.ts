/**
 * ASAR archive reader — the container format Electron packs applications
 * into. Written from the format description rather than by shelling out to
 * `asar`, so it works on a machine with nothing installed.
 *
 * Layout:  [u32 pickleLen][u32 headerSize][u32 headerPayloadLen][u32 jsonLen][json][pad][data…]
 */
import { open } from 'node:fs/promises';
import { makeEvidence, type Evidence } from './evidence.js';

export interface AsarEntry {
  /** Path inside the archive, using forward slashes. */
  path: string;
  size: number;
  /** Byte offset inside the archive's data region, or null for directories. */
  offset: number | null;
  executable: boolean;
  unpacked: boolean;
  isDirectory: boolean;
}

export interface AsarManifest {
  path: string;
  headerSize: number;
  dataOffset: number;
  entries: AsarEntry[];
  fileCount: number;
  totalSize: number;
}

interface AsarNode {
  files?: Record<string, AsarNode>;
  size?: number;
  offset?: string;
  executable?: boolean;
  unpacked?: boolean;
}

/** Read the manifest of an .asar archive. */
export async function readAsarManifest(path: string): Promise<AsarManifest> {
  const handle = await open(path, 'r');
  try {
    const header = Buffer.alloc(16);
    const { bytesRead } = await handle.read(header, 0, 16, 0);
    if (bytesRead < 16) throw new Error('truncated ASAR header');
    if (header.readUInt32LE(0) !== 4) throw new Error('unexpected ASAR header pickle');
    const headerSize = header.readUInt32LE(4);
    const jsonLength = header.readUInt32LE(12);

    if (headerSize <= 0 || headerSize > 64 * 1024 * 1024) {
      throw new Error(`implausible ASAR header size ${headerSize}`);
    }
    const jsonBuffer = Buffer.alloc(jsonLength);
    await handle.read(jsonBuffer, 0, jsonLength, 16);

    let parsed: { files?: Record<string, AsarNode> };
    try {
      parsed = JSON.parse(jsonBuffer.toString('utf8')) as { files?: Record<string, AsarNode> };
    } catch (error) {
      throw new Error(`invalid ASAR header JSON: ${(error as Error).message}`);
    }

    const entries: AsarEntry[] = [];
    const collect = (node: AsarNode, prefix: string) => {
      for (const [name, child] of Object.entries(node.files ?? {})) {
        const childPath = prefix ? `${prefix}/${name}` : name;
        if (child.files) {
          entries.push({ path: childPath, size: 0, offset: null, executable: false, unpacked: false, isDirectory: true });
          collect(child, childPath);
        } else {
          entries.push({
            path: childPath,
            size: child.size ?? 0,
            offset: child.offset !== undefined ? Number(child.offset) : null,
            executable: child.executable ?? false,
            unpacked: child.unpacked ?? false,
            isDirectory: false,
          });
        }
      }
    };
    collect(parsed, '');

    const dataOffset = 8 + headerSize;
    const files = entries.filter((e) => !e.isDirectory);
    return {
      path,
      headerSize,
      dataOffset,
      entries,
      fileCount: files.length,
      totalSize: files.reduce((sum, e) => sum + e.size, 0),
    };
  } finally {
    await handle.close();
  }
}

/** Extract one file from an .asar archive into memory. */
export async function readAsarFile(manifest: AsarManifest, entryPath: string): Promise<Buffer | null> {
  const entry = manifest.entries.find((e) => e.path === entryPath && !e.isDirectory);
  if (!entry) return null;
  if (entry.unpacked) return null; // lives in the sibling .unpacked directory
  if (entry.offset === null) return null;
  const handle = await open(manifest.path, 'r');
  try {
    const buffer = Buffer.alloc(entry.size);
    if (entry.size > 0) {
      await handle.read(buffer, 0, entry.size, manifest.dataOffset + entry.offset);
    }
    return buffer;
  } finally {
    await handle.close();
  }
}

/** Evidence for an ASAR archive. */
export async function asarEvidence(path: string): Promise<{ manifest: AsarManifest; evidence: Evidence }> {
  const manifest = await readAsarManifest(path);
  const topLevel = new Set(manifest.entries.map((e) => e.path.split('/')[0]));
  const executable = manifest.entries.filter((e) => e.executable).map((e) => e.path);

  const evidence = makeEvidence({
    kind: 'asar',
    subject: path,
    summary:
      `ASAR archive with ${manifest.fileCount} files (${manifest.totalSize} bytes of payload) ` +
      `under ${topLevel.size} top-level entries; ${executable.length} marked executable.`,
    facts: [
      { label: 'asar.files', value: String(manifest.fileCount) },
      { label: 'asar.payload_bytes', value: String(manifest.totalSize) },
      { label: 'asar.data_offset', value: String(manifest.dataOffset) },
      { label: 'asar.executable_entries', value: String(executable.length) },
      { label: 'asar.top_level', value: [...topLevel].join(', ') },
    ],
    metrics: [
      { label: 'asar.files', value: manifest.fileCount },
      { label: 'asar.payload_bytes', value: manifest.totalSize },
    ],
    limitations: [
      'Unpacked entries live in the sibling .unpacked directory and are not part of this archive.',
    ],
    data: {
      headerSize: manifest.headerSize,
      dataOffset: manifest.dataOffset,
      fileCount: manifest.fileCount,
      totalSize: manifest.totalSize,
      topLevel: [...topLevel],
      entries: manifest.entries.slice(0, 5000),
    },
  });

  return { manifest, evidence };
}
