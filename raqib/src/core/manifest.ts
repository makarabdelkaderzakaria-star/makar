/**
 * Reading a JSON manifest.
 *
 * A `package.json` is the first thing anyone looks at when they pick up an
 * unfamiliar application: it names the app, its version, its entry point,
 * its dependencies and its scripts. Reading it as text is easy; reading it
 * as *structure* — and saying what it does not prove — is the job.
 */
import { readFile } from 'node:fs/promises';
import { basename } from 'node:path';
import { makeEvidence, type Evidence } from './evidence.js';

export interface ManifestReport {
  path: string;
  format: 'package-manifest' | 'json';
  name: string | null;
  version: string | null;
  description: string | null;
  private: boolean;
  main: string | null;
  module: string | null;
  types: string | null;
  license: string | null;
  engines: Record<string, string>;
  os: string[];
  cpu: string[];
  dependencies: Record<string, string>;
  devDependencies: Record<string, string>;
  scripts: Record<string, string>;
  bin: Record<string, string>;
  electron: Record<string, unknown> | null;
  topLevelKeys: string[];
  jsonType: string | null;
  bytes: number;
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function asStringMap(value: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, item] of Object.entries(asRecord(value))) {
    if (typeof item === 'string') out[key] = item;
  }
  return out;
}

function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : [];
}

/** Read a JSON file and describe what it says. */
export async function readManifest(path: string): Promise<ManifestReport> {
  const raw = await readFile(path, 'utf8');
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new Error(`${path} is not valid JSON: ${(error as Error).message}`);
  }

  const root = asRecord(parsed);
  const looksLikePackage =
    typeof root.name === 'string'
    && (typeof root.version === 'string' || root.version === undefined)
    && ('dependencies' in root || 'devDependencies' in root || 'main' in root || 'scripts' in root);

  // Electron settings are declared in half a dozen places, depending on who
  // built the app: electron-builder, electron-forge, or a plain script.
  const build = asRecord(root.build);
  const config = asRecord(root.config);
  const electronSources: Array<Record<string, unknown>> = [build, config, root];
  let electron: Record<string, unknown> | null = null;
  for (const source of electronSources) {
    if ('electronVersion' in source && typeof source.electronVersion === 'string') {
      electron = { ...(electron ?? {}), version: source.electronVersion };
      break;
    }
  }
  if (!electron) {
    for (const source of electronSources) {
      const nested = source.electron;
      if (typeof nested === 'string') {
        electron = { version: nested };
        break;
      }
      if (nested && typeof nested === 'object' && !Array.isArray(nested)) {
        electron = { ...(nested as Record<string, unknown>) };
        break;
      }
    }
  }
  if (!electron && typeof root.electron === 'string') {
    electron = { version: root.electron };
  }

  return {
    path,
    format: looksLikePackage ? 'package-manifest' : 'json',
    name: typeof root.name === 'string' ? root.name : null,
    version: typeof root.version === 'string' ? root.version : null,
    description: typeof root.description === 'string' ? root.description : null,
    private: root.private === true,
    main: typeof root.main === 'string' ? root.main : null,
    module: typeof root.module === 'string' ? root.module : null,
    types: typeof root.types === 'string' ? root.types : null,
    license: typeof root.license === 'string' ? root.license : null,
    engines: asStringMap(root.engines),
    os: asStringArray(root.os),
    cpu: asStringArray(root.cpu),
    dependencies: asStringMap(root.dependencies),
    devDependencies: asStringMap(root.devDependencies),
    scripts: asStringMap(root.scripts),
    bin: asStringMap(root.bin),
    electron,
    topLevelKeys: Object.keys(root).sort(),
    jsonType: Array.isArray(parsed) ? 'array' : parsed === null ? 'null' : typeof parsed,
    bytes: Buffer.byteLength(raw, 'utf8'),
  };
}

/** A manifest, as an Evidence record. */
export async function manifestEvidence(path: string): Promise<Evidence> {
  const report = await readManifest(path);

  const facts: Array<{ label: string; value: string }> = [];
  const push = (label: string, value: string | number | boolean | null | undefined) => {
    if (value === null || value === undefined || value === '') return;
    facts.push({ label, value: String(value) });
  };

  push('manifest.format', report.format);
  push('manifest.name', report.name);
  push('manifest.version', report.version);
  push('manifest.description', report.description);
  if (report.private) push('manifest.private', true);
  push('manifest.main', report.main);
  push('manifest.module', report.module);
  push('manifest.types', report.types);
  push('manifest.license', report.license);
  push('manifest.dependencies', Object.keys(report.dependencies).length);
  push('manifest.dev_dependencies', Object.keys(report.devDependencies).length);
  push('manifest.scripts', Object.keys(report.scripts).length);
  push('manifest.bin', Object.keys(report.bin).length);
  push('manifest.top_level_keys', report.topLevelKeys.length);
  push('manifest.bytes', report.bytes);
  if (report.electron) {
    const electronVersion = report.electron.version;
    push('manifest.electron_version', typeof electronVersion === 'string' ? electronVersion : null);
  }

  const metrics = [
    { label: 'manifest.dependencies', value: Object.keys(report.dependencies).length },
    { label: 'manifest.scripts', value: Object.keys(report.scripts).length },
    { label: 'manifest.bytes', value: report.bytes },
  ];

  const limitations = [
    'A manifest declares intent; the shipped code may not match it.',
    'Versions here are the declared versions, not the versions actually installed.',
  ];
  if (report.format === 'json') {
    limitations.push('This file is not a package manifest, so its keys are described but not interpreted.');
  }
  if (Object.keys(report.dependencies).length === 0) {
    limitations.push('No runtime dependencies are declared.');
  }

  const summary = report.format === 'package-manifest'
    ? `${report.name ?? basename(report.path)}${report.version ? ` ${report.version}` : ''}: ` +
      `${Object.keys(report.dependencies).length} runtime dependenc${Object.keys(report.dependencies).length === 1 ? 'y' : 'ies'}, ` +
      `${Object.keys(report.scripts).length} script(s)` +
      `${report.main ? `, entry point ${report.main}` : ''}.`
    : `A JSON document with ${report.topLevelKeys.length} top-level key(s) (${report.bytes} bytes).`;

  return makeEvidence({
    kind: 'manifest',
    subject: report.path,
    summary,
    facts,
    metrics,
    limitations,
    data: report as unknown as Record<string, unknown>,
  });
}
