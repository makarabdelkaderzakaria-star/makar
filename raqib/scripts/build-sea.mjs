#!/usr/bin/env node
/**
 * Build `dist/Raqib.exe` — a real, standalone Windows executable.
 *
 * The technique is Node's own Single Executable Application: the program is
 * bundled into one CommonJS file, that file is turned into a blob, and the
 * blob is injected into a copy of the Node runtime. The result is one file
 * that carries its own JavaScript engine and needs nothing installed.
 *
 *   node scripts/build-sea.mjs [--node <node.exe>] [--node-version <v>] [--out <path>]
 *
 * The base runtime is a Windows `node.exe`. It is taken from:
 *
 *   1. --node <path>          an explicit node.exe
 *   2. RAQIB_BASE_NODE        an environment variable
 *   3. the npm package `node-win-x64`, downloaded from the npm registry
 *
 * The npm route is what makes the build reproducible from a clean machine
 * with nothing but Node installed.
 */
import { build } from 'esbuild';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmodSync, copyFileSync, existsSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync,
} from 'node:fs';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';
import { commonOptions, root } from './esbuild-plugins.mjs';

const args = process.argv.slice(2);
function flag(name, fallback = undefined) {
  const index = args.indexOf(`--${name}`);
  return index >= 0 && args[index + 1] ? args[index + 1] : fallback;
}

const NODE_VERSION = flag('node-version', '22.23.4');
const OUT = flag('out', join(root, 'dist', 'Raqib.exe'));
const SEA_DIR = join(root, 'dist', 'sea');

/** The fuse that tells the Node runtime to look for the blob inside itself. */
const SENTINEL_FUSE = 'NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2';

// ---------------------------------------------------------------------------
// 1. the CommonJS bundle
// ---------------------------------------------------------------------------

async function buildBundle() {
  mkdirSync(SEA_DIR, { recursive: true });

  // The worker first: the executable embeds its source.
  await build({
    ...commonOptions({ format: 'cjs', runtime: 'sea' }),
    entryPoints: [join(root, 'src/core/searchWorker.ts')],
    outfile: join(SEA_DIR, 'searchWorker.cjs'),
    minify: true,
    sourcemap: false,
  });

  await build({
    ...commonOptions({ format: 'cjs', runtime: 'sea' }),
    entryPoints: [join(root, 'src/cli.ts')],
    outfile: join(SEA_DIR, 'raqib.cjs'),
    minify: true,
    sourcemap: false,
  });

  return join(SEA_DIR, 'raqib.cjs');
}

// ---------------------------------------------------------------------------
// 2. the base Windows runtime
// ---------------------------------------------------------------------------

function downloadWindowsNode() {
  const url = `https://registry.npmjs.org/node-win-x64/-/node-win-x64-${NODE_VERSION}.tgz`;
  const stage = join(tmpdir(), `raqib-node-${NODE_VERSION}`);
  rmSync(stage, { recursive: true, force: true });
  mkdirSync(stage, { recursive: true });

  const archive = join(stage, 'node.tgz');
  console.log(`raqib: fetching the Windows runtime ${NODE_VERSION} from the npm registry`);
  execFileSync('curl', ['-sL', '--max-time', '600', '-o', archive, url], { stdio: 'inherit' });

  execFileSync('tar', ['-xzf', archive, '-C', stage], { stdio: 'inherit' });
  const exe = join(stage, 'package', 'bin', 'node.exe');
  if (!existsSync(exe)) throw new Error(`the archive did not contain package/bin/node.exe`);

  const target = join(root, 'dist', 'node-win-x64.exe');
  copyFileSync(exe, target);
  return target;
}

function baseRuntime() {
  const explicit = flag('node') || process.env.RAQIB_BASE_NODE;
  if (explicit) {
    if (!existsSync(explicit)) throw new Error(`no such file: ${explicit}`);
    console.log(`raqib: using the base runtime ${explicit}`);
    return explicit;
  }
  const cached = join(root, 'dist', 'node-win-x64.exe');
  if (existsSync(cached)) {
    console.log('raqib: using the cached Windows runtime dist/node-win-x64.exe');
    return cached;
  }
  return downloadWindowsNode();
}

// ---------------------------------------------------------------------------
// 3. the blob, and the injection
// ---------------------------------------------------------------------------

function makeBlob(bundle) {
  const config = {
    main: bundle,
    output: join(SEA_DIR, 'sea-prep.blob'),
    disableExperimentalSEAWarning: true,
    useSnapshot: false,
    // A code cache is tied to the exact V8 build that produced it. The blob
    // is made here and injected into a runtime downloaded elsewhere, so the
    // cache is left off: correctness over a few milliseconds of start-up.
    useCodeCache: false,
  };
  const configPath = join(SEA_DIR, 'sea-config.json');
  writeFileSync(configPath, JSON.stringify(config, null, 2), 'utf8');

  execFileSync(process.execPath, ['--experimental-sea-config', configPath], { stdio: 'inherit' });
  return config.output;
}

function inject(blob, runtime) {
  mkdirSync(dirname(OUT), { recursive: true });
  rmSync(OUT, { force: true });
  copyFileSync(runtime, OUT);
  chmodSync(OUT, 0o755);

  // postject is run through node rather than through its bin shim: a .cmd
  // shim cannot be spawned directly on Windows without a shell.
  const postject = join(root, 'node_modules', 'postject', 'dist', 'cli.js');
  if (!existsSync(postject)) {
    throw new Error('postject is missing — run: npm install');
  }
  execFileSync(process.execPath, [
    postject,
    OUT,
    'NODE_SEA_BLOB',
    blob,
    '--sentinel-fuse',
    SENTINEL_FUSE,
  ], { stdio: 'inherit' });
}

// ---------------------------------------------------------------------------

const bundle = await buildBundle();
console.log(`raqib: bundled ${bundle}`);

const blob = makeBlob(bundle);
console.log(`raqib: blob ${(statSync(blob).size / 1024).toFixed(1)} KiB`);

const runtime = baseRuntime();
inject(blob, runtime);

const digest = createHash('sha256').update(readFileSync(OUT)).digest('hex');
const size = statSync(OUT).size;
console.log(`raqib: built ${OUT}`);
console.log(`  size  : ${(size / 1024 / 1024).toFixed(1)} MiB`);
console.log(`  sha256: ${digest}`);
