/**
 * Small shared helpers: filesystem walking, hashing, formatting, timing.
 * No third-party dependencies anywhere in Raqib.
 */
import { createHash } from 'node:crypto';
import { promises as fs, constants as fsConstants } from 'node:fs';
import { join, relative, resolve, sep, extname, basename } from 'node:path';
import { cpus } from 'node:os';

/** Directories that are never worth indexing in a source or application tree. */
export const DEFAULT_IGNORE_DIRS = new Set([
  '.git', '.hg', '.svn', 'node_modules', '.pnpm', '.yarn', 'target', 'dist',
  'build', 'out', '.next', '.nuxt', '.cache', '.venv', 'venv', '__pycache__',
  '.pytest_cache', '.mypy_cache', '.turbo', '.parcel-cache', 'coverage',
  '.gradle', '.idea', '.vscode-test', 'obj', 'bin', 'obj-x86_64', '.deps',
]);

const TEXT_EXTENSIONS = new Set([
  '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.mts', '.cts', '.json', '.jsonc',
  '.html', '.htm', '.css', '.scss', '.less', '.md', '.markdown', '.txt', '.yml',
  '.yaml', '.toml', '.ini', '.cfg', '.conf', '.env', '.py', '.rb', '.go', '.rs',
  '.c', '.h', '.cc', '.cpp', '.hpp', '.cs', '.java', '.kt', '.swift', '.m', '.mm',
  '.sh', '.bash', '.zsh', '.ps1', '.bat', '.cmd', '.xml', '.svg', '.gn', '.gni',
  '.gyp', '.gypi', '.gradle', '.proto', '.graphql', '.sql', '.vue', '.svelte',
  '.dart', '.lua', '.pl', '.php', '.r', '.jl', '.nim', '.zig', '.v', '.sv',
  '.asm', '.s', '.map', '.lock', '.gitignore', '.editorconfig', '.eslintrc',
]);

/** Extension -> coarse language label used in the inventory report. */
export const LANGUAGE_BY_EXTENSION: Record<string, string> = {
  ts: 'TypeScript', tsx: 'TypeScript', mts: 'TypeScript', cts: 'TypeScript',
  js: 'JavaScript', jsx: 'JavaScript', mjs: 'JavaScript', cjs: 'JavaScript',
  json: 'JSON', jsonc: 'JSON', map: 'JSON',
  html: 'HTML', htm: 'HTML', vue: 'Vue', svelte: 'Svelte',
  css: 'CSS', scss: 'CSS', less: 'CSS',
  md: 'Markdown', markdown: 'Markdown', txt: 'Text', rst: 'Text',
  py: 'Python', rb: 'Ruby', go: 'Go', rs: 'Rust', zig: 'Zig', nim: 'Nim',
  c: 'C', h: 'C', cc: 'C++', cpp: 'C++', hpp: 'C++', cxx: 'C++',
  cs: 'C#', java: 'Java', kt: 'Kotlin', swift: 'Swift', m: 'Objective-C', mm: 'Objective-C++',
  sh: 'Shell', bash: 'Shell', zsh: 'Shell', ps1: 'PowerShell', bat: 'Batch',
  gn: 'GN', gni: 'GN', gyp: 'GYP', gypi: 'GYP',
  xml: 'XML', svg: 'SVG', proto: 'Protobuf', graphql: 'GraphQL', sql: 'SQL',
  yml: 'YAML', yaml: 'YAML', toml: 'TOML', ini: 'INI', cfg: 'Config', conf: 'Config',
  env: 'Config', lua: 'Lua', dart: 'Dart', php: 'PHP', pl: 'Perl', r: 'R',
  jl: 'Julia', v: 'Verilog', sv: 'SystemVerilog', asm: 'Assembly', s: 'Assembly',
  lock: 'Lock', png: 'Binary', jpg: 'Binary', jpeg: 'Binary', gif: 'Binary',
  webp: 'Binary', ico: 'Binary', pdf: 'Binary', zip: 'Archive', gz: 'Archive',
  wasm: 'Binary', so: 'Binary', dll: 'Binary', dylib: 'Binary', exe: 'Binary',
  pak: 'Binary', bin: 'Binary', dat: 'Binary', db: 'Binary', sqlite: 'Binary',
};

export interface WalkOptions {
  ignoreDirs?: Set<string>;
  maxFileBytes?: number;
  followSymlinks?: boolean;
  maxDepth?: number;
}

export interface WalkEntry {
  /** Absolute path. */
  path: string;
  /** Path relative to the walk root, using forward slashes. */
  rel: string;
  name: string;
  ext: string;
  size: number;
  isDirectory: boolean;
  isSymlink: boolean;
}

/**
 * Depth-first directory walk. Symlinked directories are reported but never
 * followed by default: a browser app or source tree can contain link loops
 * that would turn a five second scan into a five minute one.
 */
export async function walk(root: string, options: WalkOptions = {}): Promise<WalkEntry[]> {
  const ignore = options.ignoreDirs ?? DEFAULT_IGNORE_DIRS;
  const follow = options.followSymlinks ?? false;
  const maxDepth = options.maxDepth ?? 64;
  const out: WalkEntry[] = [];

  const stack: Array<{ dir: string; depth: number }> = [{ dir: root, depth: 0 }];
  while (stack.length > 0) {
    const { dir, depth } = stack.pop()!;
    let entries;
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      continue; // unreadable directory: skip rather than fail the whole scan
    }
    for (const entry of entries) {
      const full = join(dir, entry.name);
      const rel = relative(root, full).split(sep).join('/');
      let stat;
      try {
        stat = await fs.lstat(full);
      } catch {
        continue;
      }
      const isSymlink = stat.isSymbolicLink();
      let isDirectory = stat.isDirectory();
      let size = stat.size;

      if (isSymlink) {
        if (!follow) {
          // A symlink is reported but never followed: link loops turn a
          // five second scan into a five minute one.
          out.push({
            path: full, rel, name: entry.name,
            ext: extname(entry.name).toLowerCase(),
            size, isDirectory: false, isSymlink: true,
          });
          continue;
        }
        try {
          const target = await fs.stat(full);
          isDirectory = target.isDirectory();
          size = target.size;
        } catch {
          continue;
        }
      }

      out.push({
        path: full, rel, name: entry.name,
        ext: extname(entry.name).toLowerCase(),
        size, isDirectory, isSymlink,
      });

      if (isDirectory && !ignore.has(entry.name) && depth < maxDepth) {
        stack.push({ dir: full, depth: depth + 1 });
      }
    }
  }
  out.sort((a, b) => (a.rel < b.rel ? -1 : a.rel > b.rel ? 1 : 0));
  return out;
}

/** Read a file, returning null when it is missing or unreadable. */
export async function readFileSafe(file: string): Promise<Buffer | null> {
  try {
    return await fs.readFile(file);
  } catch {
    return null;
  }
}

export async function readTextSafe(file: string): Promise<string | null> {
  const buf = await readFileSafe(file);
  if (!buf) return null;
  return buf.toString('utf8');
}

export async function exists(file: string): Promise<boolean> {
  try {
    await fs.access(file, fsConstants.F_OK);
    return true;
  } catch {
    return false;
  }
}

export async function isDirectory(path: string): Promise<boolean> {
  try {
    return (await fs.stat(path)).isDirectory();
  } catch {
    return false;
  }
}

/** Heuristic binary detection: a NUL byte in the first 8 KiB. */
export function looksBinary(buf: Buffer): boolean {
  const limit = Math.min(buf.length, 8192);
  for (let i = 0; i < limit; i += 1) {
    if (buf[i] === 0) return true;
  }
  return false;
}

export function isTextPath(path: string): boolean {
  const ext = extname(path).toLowerCase();
  if (!ext) return true; // extensionless files are usually text (LICENSE, Makefile…)
  if (TEXT_EXTENSIONS.has(ext)) return true;
  const name = basename(path).toLowerCase();
  return name === 'makefile' || name === 'dockerfile' || name === 'license' || name.startsWith('readme');
}

export function languageOf(path: string): string {
  const ext = extname(path).toLowerCase().replace('.', '');
  return LANGUAGE_BY_EXTENSION[ext] ?? (ext ? ext.toUpperCase() : 'Unknown');
}

/** Stable content hash used for evidence identity. */
export function sha256(input: string | Buffer): string {
  return createHash('sha256').update(input).digest('hex');
}

/** 16 hex characters is plenty for an in-memory evidence identity. */
export function shortHash(input: string | Buffer): string {
  return sha256(input).slice(0, 16);
}

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes)) return '—';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value < 10 && unit > 0 ? value.toFixed(1) : Math.round(value)} ${units[unit]}`;
}

export function formatDuration(ms: number): string {
  if (ms < 1) return `${(ms * 1000).toFixed(0)} µs`;
  if (ms < 1000) return `${ms.toFixed(1)} ms`;
  return `${(ms / 1000).toFixed(2)} s`;
}

export function workerCount(): number {
  return Math.max(1, Math.min(8, (cpus()?.length ?? 2) - 1));
}

/** Trim a path for display: keep the tail, which is the informative part. */
export function displayPath(path: string, max = 96): string {
  if (path.length <= max) return path;
  return `…${path.slice(path.length - (max - 1))}`;
}

export function nowIso(): string {
  return new Date().toISOString();
}

export function resolvePath(input: string, base = process.cwd()): string {
  return resolve(base, input);
}
