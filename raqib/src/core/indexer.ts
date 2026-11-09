/**
 * Tree inventory: what is in a directory, how big it is, and which languages
 * it is written in. This is the first thing an agent asks for and the first
 * thing a human wants to see in the console.
 */
import { basename, extname } from 'node:path';
import { walk, languageOf, formatBytes, DEFAULT_IGNORE_DIRS, type WalkEntry } from './util.js';

export interface LanguageStat {
  language: string;
  files: number;
  bytes: number;
}

export interface TopLevelStat {
  name: string;
  files: number;
  bytes: number;
}

export interface TreeIndex {
  root: string;
  fileCount: number;
  directoryCount: number;
  totalBytes: number;
  textBytes: number;
  languages: LanguageStat[];
  extensions: Array<{ extension: string; files: number; bytes: number }>;
  largestFiles: Array<{ path: string; bytes: number }>;
  topLevel: TopLevelStat[];
  /** Files that usually hold the answer: manifests, build files, entry points. */
  notable: Array<{ path: string; bytes: number; why: string }>;
  ignoredDirectories: string[];
  elapsedMs: number;
}

const NOTABLE_NAMES = new Map<string, string>([
  ['package.json', 'npm manifest'],
  ['pnpm-lock.yaml', 'package manager lockfile'],
  ['yarn.lock', 'package manager lockfile'],
  ['Cargo.toml', 'cargo manifest'],
  ['CMakeLists.txt', 'cmake build file'],
  ['Makefile', 'make build file'],
  ['build.gradle', 'gradle build file'],
  ['pom.xml', 'maven build file'],
  ['go.mod', 'go module manifest'],
  ['deps.gn', 'chromium dependency manifest'],
  ['DEPS', 'chromium dependency manifest'],
  ['build.gn', 'gn build file'],
  ['.gn', 'gn build file'],
  ['electron-builder.yml', 'electron packaging config'],
  ['electron-builder.json', 'electron packaging config'],
  ['manifest.json', 'extension manifest'],
]);

const NOTABLE_EXTENSIONS = new Map<string, string>([
  ['.gn', 'gn build file'], ['.gni', 'gn build file'], ['.gyp', 'gyp build file'],
  ['.gypi', 'gyp build file'], ['.asar', 'electron archive'], ['.plist', 'apple property list'],
  ['.appxmanifest', 'windows package manifest'], ['.desktop', 'linux desktop entry'],
]);

/** Build an inventory of a directory tree. */
export async function indexTree(root: string, options: { maxDepth?: number; maxFiles?: number } = {}): Promise<TreeIndex> {
  const started = performance.now();
  const entries = await walk(root, { maxDepth: options.maxDepth });
  const files = entries.filter((e) => !e.isDirectory);
  const directories = entries.filter((e) => e.isDirectory);

  const languageMap = new Map<string, LanguageStat>();
  const extensionMap = new Map<string, { extension: string; files: number; bytes: number }>();
  const topLevelMap = new Map<string, TopLevelStat>();
  const notable: TreeIndex['notable'] = [];
  let totalBytes = 0;

  for (const file of files) {
    totalBytes += file.size;
    const language = languageOf(file.path);
    const stat = languageMap.get(language) ?? { language, files: 0, bytes: 0 };
    stat.files += 1;
    stat.bytes += file.size;
    languageMap.set(language, stat);

    const extension = file.ext || basename(file.path).toLowerCase();
    const extStat = extensionMap.get(extension) ?? { extension, files: 0, bytes: 0 };
    extStat.files += 1;
    extStat.bytes += file.size;
    extensionMap.set(extension, extStat);

    const top = file.rel.includes('/') ? file.rel.split('/')[0] : '.';
    const topStat = topLevelMap.get(top) ?? { name: top, files: 0, bytes: 0 };
    topStat.files += 1;
    topStat.bytes += file.size;
    topLevelMap.set(top, topStat);

    const name = basename(file.path);
    const why = NOTABLE_NAMES.get(name) ?? NOTABLE_EXTENSIONS.get(extname(file.path).toLowerCase());
    if (why) notable.push({ path: file.rel, bytes: file.size, why });
  }

  const largestFiles = [...files]
    .sort((a, b) => b.size - a.size)
    .slice(0, 25)
    .map((f) => ({ path: f.rel, bytes: f.size }));

  const languages = [...languageMap.values()].sort((a, b) => b.bytes - a.bytes);
  const extensions = [...extensionMap.values()].sort((a, b) => b.files - a.files).slice(0, 40);
  const topLevel = [...topLevelMap.values()].sort((a, b) => b.bytes - a.bytes).slice(0, 40);

  return {
    root,
    fileCount: files.length,
    directoryCount: directories.length,
    totalBytes,
    textBytes: files.filter((f) => !isBinaryExtension(f.ext)).reduce((sum, f) => sum + f.size, 0),
    languages,
    extensions,
    largestFiles,
    topLevel,
    notable: notable.slice(0, 200),
    ignoredDirectories: [...DEFAULT_IGNORE_DIRS],
    elapsedMs: performance.now() - started,
  };
}

function isBinaryExtension(ext: string): boolean {
  return ['.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.pdf', '.zip', '.gz', '.wasm',
    '.so', '.dll', '.dylib', '.exe', '.bin', '.dat', '.db', '.sqlite', '.pak', '.ttf', '.otf',
    '.woff', '.woff2', '.mp3', '.mp4', '.webm', '.ogg', '.pyc', '.class', '.node'].includes(ext);
}

export function formatIndexSummary(index: TreeIndex): string {
  const top = index.languages.slice(0, 5).map((l) => `${l.language} (${l.files})`).join(', ');
  return [
    `${index.fileCount} files, ${index.directoryCount} directories, ${formatBytes(index.totalBytes)}`,
    `languages: ${top || 'none'}`,
    `scan took ${index.elapsedMs.toFixed(0)} ms`,
  ].join('\n');
}
