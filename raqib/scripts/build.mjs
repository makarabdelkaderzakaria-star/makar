#!/usr/bin/env node
/**
 * Raqib build: one esbuild pass, zero runtime dependencies.
 *
 *  - dist/raqib.mjs        the single-file CLI / MCP server / web console host
 *  - dist/test/*.test.mjs  the compiled test files (node --test)
 *
 * The UI is inlined as text and the three web fonts are inlined as base64, so
 * the shipped artifact never reaches the network for an asset.
 */
import { build } from 'esbuild';
import { readFileSync, existsSync, mkdirSync, readdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const wantTests = process.argv.includes('--tests');
const watch = process.argv.includes('--watch');

const FONT_FILES = [
  ['bricolage', '@fontsource/bricolage-grotesque/files/bricolage-grotesque-latin-400-normal.woff2'],
  ['plexSans', '@fontsource/ibm-plex-sans/files/ibm-plex-sans-latin-400-normal.woff2'],
  ['plexSansMedium', '@fontsource/ibm-plex-sans/files/ibm-plex-sans-latin-500-normal.woff2'],
  ['plexMono', '@fontsource/ibm-plex-mono/files/ibm-plex-mono-latin-400-normal.woff2'],
  ['plexMonoMedium', '@fontsource/ibm-plex-mono/files/ibm-plex-mono-latin-500-normal.woff2'],
];

function fontData() {
  const out = {};
  for (const [key, rel] of FONT_FILES) {
    const file = join(root, 'node_modules', rel);
    if (!existsSync(file)) {
      throw new Error(`missing font asset: ${rel} (run: npm install)`);
    }
    out[key] = readFileSync(file).toString('base64');
  }
  return out;
}

/** Inline local assets (html/css/js) and the base64 font payload. */
const inlineAssets = {
  name: 'raqib-inline-assets',
  setup(pluginBuild) {
    pluginBuild.onResolve({ filter: /^\.\/ui\// }, (args) => ({
      path: resolve(args.resolveDir, args.path),
      namespace: 'raqib-ui',
    }));
    pluginBuild.onLoad({ filter: /.*/, namespace: 'raqib-ui' }, (args) => ({
      contents: readFileSync(args.path, 'utf8'),
      loader: 'text',
    }));

    pluginBuild.onResolve({ filter: /^virtual:fonts$/ }, () => ({
      path: 'fonts',
      namespace: 'raqib-fonts',
    }));
    pluginBuild.onLoad({ filter: /.*/, namespace: 'raqib-fonts' }, () => ({
      contents: `export const fonts = ${JSON.stringify(fontData())};`,
      loader: 'js',
    }));
  },
};

const common = {
  bundle: true,
  platform: 'node',
  target: 'node20',
  format: 'esm',
  logLevel: 'warning',
  legalComments: 'none',
  plugins: [inlineAssets],
};

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
  await Promise.all(targets.map((target) => build(target)));
  const { statSync } = await import('node:fs');
  const size = statSync(join(root, 'dist/raqib.mjs')).size;
  console.log(`raqib: built dist/raqib.mjs (${(size / 1024).toFixed(1)} KiB)`);
}
