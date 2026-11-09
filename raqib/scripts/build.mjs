#!/usr/bin/env node
/**
 * Raqib build: one esbuild pass, zero runtime dependencies.
 *
 *  - dist/raqib.mjs        the single-file CLI / MCP server / web console host
 *  - dist/test/*.test.mjs  the compiled test files (node --test)
 *
 * The UI is inlined as text and the three web fonts are inlined as base64,
 * so the shipped artifact never reaches the network for an asset.
 */
import { build } from 'esbuild';
import { mkdirSync, existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { commonOptions, root } from './esbuild-plugins.mjs';

const wantTests = process.argv.includes('--tests');
const watch = process.argv.includes('--watch');

const common = commonOptions({ format: 'esm', runtime: 'node' });

const targets = [
  {
    ...common,
    entryPoints: [join(root, 'src/cli.ts')],
    outfile: join(root, 'dist/raqib.mjs'),
    minify: !watch,
    sourcemap: false,
  },
  {
    ...common,
    entryPoints: [join(root, 'src/core/searchWorker.ts')],
    outfile: join(root, 'dist/searchWorker.mjs'),
    minify: !watch,
    sourcemap: false,
  },
];

if (wantTests) {
  const testDir = join(root, 'test');
  if (existsSync(testDir)) {
    for (const entry of readdirSync(testDir)) {
      if (!entry.endsWith('.test.ts')) continue;
      targets.push({
        ...common,
        entryPoints: [join(testDir, entry)],
        outfile: join(root, 'dist/test', entry.replace(/\.ts$/, '.mjs')),
        minify: false,
      });
    }
  }
}

mkdirSync(join(root, 'dist'), { recursive: true });
mkdirSync(join(root, 'dist/test'), { recursive: true });

if (watch) {
  const { context } = await import('esbuild');
  for (const target of targets) {
    const ctx = await context(target);
    await ctx.watch();
  }
  console.log('raqib: watching');
} else {
  // The worker is built first: the CLI embeds its source, so the CLI cannot
  // be built until the worker exists.
  const workerTarget = targets.find((t) => t.outfile.endsWith('searchWorker.mjs'));
  const rest = targets.filter((t) => t !== workerTarget);
  if (workerTarget) await build(workerTarget);
  await Promise.all(rest.map((target) => build(target)));
  const { statSync } = await import('node:fs');
  const size = statSync(join(root, 'dist/raqib.mjs')).size;
  console.log(`raqib: built dist/raqib.mjs (${(size / 1024).toFixed(1)} KiB)`);
}
