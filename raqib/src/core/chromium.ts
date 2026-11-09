/**
 * Chromium-family analysis.
 *
 * Two jobs:
 *
 *  1. Read a Chromium-derived *source tree* (brave-core, chromium, or any
 *     fork) and map the privacy subsystems that are actually present, with
 *     the files that implement them.
 *  2. Identify an *installed* Chromium-family browser from its binaries, by
 *     reading the version markers and the compiled-in feature strings rather
 *     than trusting a file name.
 */
import { readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { basename, join, win32 } from 'node:path';
import { makeEvidence, type Evidence, type Fact, type SourceLocation } from './evidence.js';
import { walk, formatBytes, DEFAULT_IGNORE_DIRS } from './util.js';
import { extractStrings, type ExtractedString } from './strings.js';

export interface SubsystemHit {
  subsystem: string;
  description: string;
  /** Files that implement it. */
  files: string[];
  /** Files that only mention it. */
  mentions: string[];
}

export interface GnArgument {
  name: string;
  value: string | null;
  file: string;
  line: number;
}

export interface ChromiumTreeAnalysis {
  kind: 'chromium-tree';
  root: string;
  flavour: 'brave' | 'chromium' | 'edge' | 'vivaldi' | 'opera' | 'unknown';
  evidence: string[];
  buildArguments: GnArgument[];
  subsystems: SubsystemHit[];
  fileCount: number;
  totalBytes: number;
  topLevel: string[];
  limitations: string[];
}

/** Files whose names point at a privacy-relevant subsystem. */
const SUBSYSTEM_FILE_HINTS: Array<{ subsystem: string; description: string; pattern: RegExp; content?: RegExp }> = [
  { subsystem: 'fingerprinting', description: 'Fingerprinting protection / canvas, font and hardware noise', pattern: /fingerprint/i, content: /fingerprint/i },
  { subsystem: 'shields', description: 'Per-site content blocking (Shields)', pattern: /shield/i },
  { subsystem: 'ad-blocking', description: 'Ad and tracker filtering lists', pattern: /(ad_?block|ads_?(filter|block)|blocklist)/i },
  { subsystem: 'tracker-blocking', description: 'Network tracker classification', pattern: /tracker/i },
  { subsystem: 'debouncing', description: 'Tracker debouncing / bounce tracking mitigation', pattern: /debounc/i },
  { subsystem: 'privacy-budget', description: 'Privacy budget accounting for aggregate anonymity', pattern: /privacy_?budget/i },
  { subsystem: 'tor', description: 'Tor circuit integration', pattern: /\btor\b|tor_/i },
  { subsystem: 'rewards', description: 'Brave Rewards / BAT tokenisation', pattern: /reward/i },
  { subsystem: 'assistant', description: 'The built-in AI assistant', pattern: /\bleo\b|assistant/i },
  { subsystem: 'search', description: 'Private search integration', pattern: /search/i, content: /brave_search/i },
  { subsystem: 'sync', description: 'Encrypted sync', pattern: /sync/i },
  { subsystem: 'vpn', description: 'Built-in VPN', pattern: /\bvpn\b/i },
  { subsystem: 'crypto-wallet', description: 'Crypto wallet', pattern: /wallet/i },
  { subsystem: 'p2p', description: 'Peer-to-peer content and Brave Today', pattern: /brave_?today|p2p/i },
  { subsystem: 'update', description: 'Update and promotion pipeline', pattern: /promotion|update/i },
];

const BRAVE_PATH_HINTS = /(^|\/)(brave|brave_ads|brave_core|brave_rewards|brave_shields|brave_search|brave_vpn|brave_leo|brave_sync)(\/|$)/i;

/** Analyse a Chromium-derived source tree. */
export async function analyzeChromiumTree(root: string): Promise<ChromiumTreeAnalysis> {
  const started = performance.now();
  // A Chromium checkout keeps its build arguments in build/args — exactly the
  // directory a generic walk skips, so this analysis keeps it.
  const ignoreDirs = new Set([...DEFAULT_IGNORE_DIRS].filter((name) => name !== 'build'));
  const entries = await walk(root, { ignoreDirs });
  const files = entries.filter((e) => !e.isDirectory);
  const limitations: string[] = [];

  const flavourEvidence: string[] = [];
  let flavour: ChromiumTreeAnalysis['flavour'] = 'unknown';

  const braveFiles = files.filter((f) => BRAVE_PATH_HINTS.test(f.rel));
  if (braveFiles.length > 0) {
    flavour = 'brave';
    flavourEvidence.push(`${braveFiles.length} path(s) match a Brave component namespace`);
  }
  if (files.some((f) => f.rel.endsWith('brave.gn') || f.rel.includes('brave/brave.gni'))) {
    flavour = 'brave';
    flavourEvidence.push('a brave.gn / brave.gni build configuration is present');
  }
  if (flavour === 'unknown') {
    if (files.some((f) => f.rel.startsWith('chrome/')) && files.some((f) => f.rel.startsWith('content/'))) {
      flavour = 'chromium';
      flavourEvidence.push('the chrome/ and content/ trees are present');
    }
  }

  // Build arguments from GN files.
  const buildArguments: GnArgument[] = [];
  const gnFiles = files.filter((f) => f.ext === '.gn' || f.ext === '.gni' || f.rel.endsWith('BUILD.gn'));
  const gnLimits = 400;
  for (const file of gnFiles.slice(0, gnLimits)) {
    if (file.size > 512 * 1024) continue;
    let text: string;
    try {
      text = await readFile(file.path, 'utf8');
    } catch {
      continue;
    }
    const lines = text.split('\n');
    for (let i = 0; i < lines.length; i += 1) {
      const match = /^\s*([a-z0-9_]+)\s*=\s*(.+?)\s*$/.exec(lines[i]);
      if (!match) continue;
      const name = match[1];
      if (!/brave|chrome|chromium|enable_|use_|disable_/.test(name)) continue;
      if (name.length < 4) continue;
      buildArguments.push({ name, value: match[2].replace(/,$/, ''), file: file.rel, line: i + 1 });
      if (buildArguments.length > 2000) break;
    }
    if (buildArguments.length > 2000) break;
  }
  if (gnFiles.length > gnLimits) {
    limitations.push(`Only the first ${gnLimits} GN files were read for build arguments.`);
  }

  // Privacy subsystems: match file names first, then confirm by content.
  const subsystemMap = new Map<string, SubsystemHit>();
  const candidates = files.filter((f) => f.ext === '.cc' || f.ext === '.h' || f.ext === '.js' || f.ext === '.ts' || f.ext === '.json' || f.ext === '.gn' || f.ext === '.gni');

  for (const file of candidates) {
    for (const hint of SUBSYSTEM_FILE_HINTS) {
      if (!hint.pattern.test(file.rel)) continue;
      let hit = subsystemMap.get(hint.subsystem);
      if (!hit) {
        hit = { subsystem: hint.subsystem, description: hint.description, files: [], mentions: [] };
        subsystemMap.set(hint.subsystem, hit);
      }
      let confirmed = !hint.content;
      if (hint.content && file.size < 2 * 1024 * 1024) {
        try {
          const text = await readFile(file.path, 'utf8');
          confirmed = hint.content.test(text);
        } catch {
          confirmed = false;
        }
      }
      if (confirmed) {
        if (hit.files.length < 40) hit.files.push(file.rel);
      } else if (hit.mentions.length < 20) {
        hit.mentions.push(file.rel);
      }
    }
  }

  const subsystems = [...subsystemMap.values()].sort((a, b) => b.files.length - a.files.length);
  if (subsystems.length === 0) {
    limitations.push('No privacy subsystem could be matched by name; the tree may not be a Chromium fork, or may use different naming.');
  }

  const topLevel = [...new Set(files.map((f) => (f.rel.includes('/') ? f.rel.split('/')[0] : '.')))].slice(0, 40);

  const analysis: ChromiumTreeAnalysis = {
    kind: 'chromium-tree',
    root,
    flavour,
    evidence: flavourEvidence,
    buildArguments: buildArguments.slice(0, 500),
    subsystems,
    fileCount: files.length,
    totalBytes: files.reduce((sum, f) => sum + f.size, 0),
    topLevel,
    limitations,
  };

  void started;
  return analysis;
}

/** Evidence for a Chromium tree analysis. */
export function chromiumTreeEvidence(analysis: ChromiumTreeAnalysis): Evidence {
  const facts: Fact[] = [];
  const push = (label: string, value: string | number | boolean) => facts.push({ label, value: String(value) });
  const locations: SourceLocation[] = [];

  push('tree.flavour', analysis.flavour);
  push('tree.files', analysis.fileCount);
  push('tree.bytes', analysis.totalBytes);
  push('tree.build_arguments', analysis.buildArguments.length);
  push('tree.subsystems', analysis.subsystems.length);
  for (const subsystem of analysis.subsystems) {
    push(`subsystem.${subsystem.subsystem}`, subsystem.files.length);
    for (const file of subsystem.files.slice(0, 5)) {
      locations.push({ file, note: `${subsystem.subsystem}: ${subsystem.description}` });
    }
  }

  return makeEvidence({
    kind: 'chromium-tree',
    subject: analysis.root,
    summary:
      `${analysis.flavour === 'unknown' ? 'Unidentified' : analysis.flavour} Chromium-family tree with ` +
      `${analysis.fileCount} files (${formatBytes(analysis.totalBytes)}); ` +
      `${analysis.subsystems.length} privacy subsystem(s) matched and ` +
      `${analysis.buildArguments.length} build argument(s) extracted.`,
    facts,
    locations,
    metrics: [
      { label: 'tree.files', value: analysis.fileCount },
      { label: 'tree.subsystems', value: analysis.subsystems.length },
      { label: 'tree.build_arguments', value: analysis.buildArguments.length },
    ],
    limitations: analysis.limitations,
    data: {
      flavour: analysis.flavour,
      flavourEvidence: analysis.evidence,
      buildArguments: analysis.buildArguments,
      subsystems: analysis.subsystems,
      topLevel: analysis.topLevel,
    },
  });
}

export interface BrowserIdentity {
  kind: 'browser-identity';
  directory: string;
  executable: string | null;
  product: string | null;
  version: string | null;
  chromiumVersion: string | null;
  engine: string | null;
  features: string[];
  otherMarkers: string[];
  limitations: string[];
}

/**
 * How a browser names itself.
 *
 * Two shapes are looked for. Some binaries carry the combined form the user
 * agent uses — "Brave/1.62.126". Most do not: the version resource of a
 * Windows executable keeps the product name and the product version in
 * *separate* strings, so "Brave" and "1.101.38" have to be read on their
 * own and put back together.
 */
const PRODUCT_MARKERS: Array<{ pattern: RegExp; product: string; engine: string }> = [
  { pattern: /Brave\/(\d+\.\d+\.\d+)/, product: 'Brave', engine: 'Chromium' },
  { pattern: /Vivaldi\/(\d+\.\d+\.\d+)/, product: 'Vivaldi', engine: 'Chromium' },
  { pattern: /OPR\/(\d+\.\d+\.\d+)/, product: 'Opera', engine: 'Chromium' },
  { pattern: /Edg\/(\d+\.\d+\.\d+)/, product: 'Microsoft Edge', engine: 'Chromium' },
  { pattern: /Chrome\/(\d+\.\d+\.\d+)/, product: 'Google Chrome', engine: 'Chromium' },
  { pattern: /Chromium\/(\d+\.\d+\.\d+)/, product: 'Chromium', engine: 'Chromium' },
];

/** The product name on its own, as the version resource spells it. */
const PRODUCT_NAMES: Array<{ pattern: RegExp; product: string; engine: string }> = [
  { pattern: /^Brave( Browser)?$/, product: 'Brave', engine: 'Chromium' },
  { pattern: /^Google Chrome$/, product: 'Google Chrome', engine: 'Chromium' },
  { pattern: /^Microsoft Edge$/, product: 'Microsoft Edge', engine: 'Chromium' },
  { pattern: /^Vivaldi$/, product: 'Vivaldi', engine: 'Chromium' },
  { pattern: /^Chromium$/, product: 'Chromium', engine: 'Chromium' },
  { pattern: /^Opera( GX)?$/, product: 'Opera', engine: 'Chromium' },
];

/**
 * The strings worth keeping when a browser binary is read.
 *
 * Everything else is thrown away as it is found, which is what lets the
 * scan reach the end of a hundred-megabyte executable: the version
 * resource sits at the very end, long after the sixty thousandth string.
 */
const BROWSER_STRING_FILTER = new RegExp([
  '^Brave( Browser)?$',
  '^Google Chrome$',
  '^Microsoft Edge$',
  '^Vivaldi$',
  '^Chromium$',
  '^Opera( GX)?$',
  '^(Brave|Chrome|Chromium|Edge|Vivaldi|OPR)\/\d+\.\d+(\.\d+)?',
  'fingerprinting',
  'tracker.?block',
  'ad.?block',
  'debounc',
  '\\btor\\b',
  'brave.?vpn',
  'brave.?rewards',
  '\\bleo\\b',
  'brave.?wallet',
  'brave.?sync',
  'privacy.?budget',
  '^\\d+\\.\\d+\\.\\d+(\\.\\d+)?$',
].join('|'), 'i');

const FEATURE_MARKERS: Array<[string, RegExp]> = [
  ['shields', /brave[_\s-]?shields/i],
  ['fingerprinting-protection', /fingerprinting/i],
  ['tracker-blocking', /tracker.?block/i],
  ['ad-blocking', /ad.?block/i],
  ['debouncing', /debounc/i],
  ['tor', /\btor\b/i],
  ['vpn', /brave.?vpn/i],
  ['rewards', /brave.?rewards/i],
  ['ai-assistant', /\bleo\b/i],
  ['crypto-wallet', /brave.?wallet/i],
  ['sync', /brave.?sync/i],
  ['privacy-budget', /privacy.?budget/i],
];

/**
 * The version-shaped string closest to a given offset.
 *
 * In a version resource the product name and the product version sit next
 * to one another, so the nearest version-shaped string is the one that
 * belongs with it.
 */
function nearestVersion(strings: ExtractedString[], offset: number): string | null {
  const VERSION = /^\d+\.\d+\.\d+(\.\d+)?$/;
  let best: { value: string; distance: number } | null = null;
  for (const candidate of strings) {
    if (!VERSION.test(candidate.value)) continue;
    const distance = Math.abs(candidate.offset - offset);
    if (!best || distance < best.distance) best = { value: candidate.value, distance };
  }
  return best ? best.value : null;
}

/**
 * Identify an installed Chromium-family browser from its own files.
 * Nothing is trusted but the bytes: the product and version come from the
 * version strings baked into the executable.
 */
export async function identifyBrowser(directory: string): Promise<BrowserIdentity> {
  const limitations: string[] = [];
  const entries = await walk(directory, { maxDepth: 4 });
  const files = entries.filter((e) => !e.isDirectory);

  const candidates = files
    .filter((f) => f.size > 1_000_000 && (f.ext === '' || f.ext === '.exe' || f.ext === '.bin'))
    .sort((a, b) => b.size - a.size)
    .slice(0, 6);

  let executable: string | null = null;
  let product: string | null = null;
  let version: string | null = null;
  let chromiumVersion: string | null = null;
  let engine: string | null = null;
  const features = new Set<string>();
  const otherMarkers: string[] = [];

  for (const candidate of candidates) {
    const buffer = await readFile(candidate.path).catch(() => null);
    if (!buffer) continue;

    // Only the strings that could possibly matter are kept, so the scan
    // reaches the end of the file instead of stopping at the sixtieth
    // thousandth string.
    const strings = extractStrings(buffer, {
      // Short, because a product name can be short: "Brave" is five
      // characters and the filter is what does the real work.
      minLength: 4,
      maxStrings: 200000,
      filter: BROWSER_STRING_FILTER,
    });
    const haystack = strings.map((s) => s.value).join('\n');

    let matched = false;
    for (const marker of PRODUCT_MARKERS) {
      const found = marker.pattern.exec(haystack);
      if (!found) continue;
      matched = true;
      if (!product) {
        product = marker.product;
        engine = marker.engine;
        executable = candidate.path;
        version = found[1];
      }
    }

    // The version resource of a Windows executable keeps the product name
    // and the product version apart, next to one another. When the combined
    // form was not there, they are put back together by proximity.
    if (!product) {
      for (const marker of PRODUCT_NAMES) {
        const found = strings.find((s) => marker.pattern.test(s.value));
        if (!found) continue;
        matched = true;
        product = marker.product;
        engine = marker.engine;
        executable = candidate.path;
        version = nearestVersion(strings, found.offset);
        break;
      }
    }

    if (product) {
      const chrome = /Chrome\/(\d+\.\d+\.\d+)/.exec(haystack);
      if (chrome) chromiumVersion = chrome[1];
    }

    for (const [name, pattern] of FEATURE_MARKERS) {
      if (pattern.test(haystack)) features.add(name);
    }
    if (!matched && /Electron/i.test(haystack)) {
      otherMarkers.push('Electron runtime detected');
    }
    if (product) break;
  }

  if (!executable) {
    limitations.push('No executable larger than 1 MiB was found inside the directory.');
  } else {
    limitations.push('Feature detection reads strings from the binary; a feature compiled out leaves no marker.');
  }

  return {
    kind: 'browser-identity',
    directory,
    executable,
    product,
    version,
    chromiumVersion,
    engine,
    features: [...features],
    otherMarkers,
    limitations,
  };
}

/** Evidence for a browser identity. */
export function browserIdentityEvidence(identity: BrowserIdentity): Evidence {
  const facts: Fact[] = [];
  const push = (label: string, value: string | number | boolean) => facts.push({ label, value: String(value) });
  push('browser.product', identity.product ?? 'unknown');
  push('browser.version', identity.version ?? 'unknown');
  push('browser.chromium_version', identity.chromiumVersion ?? 'unknown');
  push('browser.engine', identity.engine ?? 'unknown');
  push('browser.executable', identity.executable ?? 'unknown');
  push('browser.features', identity.features.join(', ') || 'none detected');

  return makeEvidence({
    kind: 'browser-identity',
    subject: identity.directory,
    summary:
      `${identity.product ?? 'Unidentified browser'}${identity.version ? ` ${identity.version}` : ''}` +
      `${identity.chromiumVersion ? ` (Chromium ${identity.chromiumVersion})` : ''}; ` +
      `${identity.features.length} compiled-in feature marker(s) detected.`,
    facts,
    metrics: [{ label: 'browser.features', value: identity.features.length }],
    limitations: identity.limitations,
    data: identity as unknown as Record<string, unknown>,
  });
}

/**
 * The conventional install directory of every Chromium-family browser.
 *
 * Windows gets the most entries: Chromium, Edge and Vivaldi install to
 * several places depending on how they were installed, and the per-user
 * locations under `%LOCALAPPDATA%` are where most people actually find them.
 */
export function browserSearchPaths(): Array<{ label: string; path: string }> {
  // `homedir()` rather than `process.env.HOME`: on Windows HOME is usually
  // not set at all, which would silently produce a relative path.
  const home = homedir();
  // Only present on Windows. When it is missing there is no per-user install
  // directory to point at, and inventing one from a Unix home path would
  // print a path that cannot exist.
  const localAppData = process.env.LOCALAPPDATA;
  const programFiles = process.env.ProgramFiles ?? 'C:\\Program Files';
  const programFilesX86 = process.env['ProgramFiles(x86)'] ?? 'C:\\Program Files (x86)';

  return [
    { label: 'Brave (Linux)', path: '/usr/lib/brave-browser' },
    { label: 'Brave (user)', path: join(home, '.local/share/brave-browser') },
    { label: 'Chrome (Linux)', path: '/opt/google/chrome' },
    { label: 'Chromium (Linux)', path: '/usr/lib/chromium' },
    { label: 'Edge (Linux)', path: '/opt/microsoft/msedge' },
    { label: 'Vivaldi (Linux)', path: '/opt/vivaldi' },
    { label: 'Brave (macOS)', path: '/Applications/Brave Browser.app' },
    { label: 'Chrome (macOS)', path: '/Applications/Google Chrome.app' },
    // Windows paths are built with win32.join so they read as Windows paths
    // even when Raqib is the one reporting them from another machine.
    { label: 'Brave (Windows)', path: win32.join(programFiles, 'BraveSoftware', 'Brave-Browser') },
    { label: 'Chrome (Windows)', path: win32.join(programFiles, 'Google', 'Chrome') },
    { label: 'Edge (Windows)', path: win32.join(programFilesX86, 'Microsoft', 'Edge', 'Application') },
    { label: 'Opera (Windows)', path: win32.join(programFiles, 'Opera') },
    ...(localAppData
      ? [
        { label: 'Brave (Windows, user)', path: win32.join(localAppData, 'BraveSoftware', 'Brave-Browser') },
        { label: 'Chrome (Windows, user)', path: win32.join(localAppData, 'Google', 'Chrome') },
        { label: 'Chromium (Windows)', path: win32.join(localAppData, 'Chromium', 'Application') },
        { label: 'Edge (Windows, user)', path: win32.join(localAppData, 'Microsoft', 'Edge', 'Application') },
        { label: 'Vivaldi (Windows)', path: win32.join(localAppData, 'Vivaldi', 'Application') },
      ]
      : []),
  ];
}

export function describeBrowserPath(root: string): string {
  return basename(root);
}
