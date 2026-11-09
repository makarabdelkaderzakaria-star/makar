/**
 * The esbuild plugins and options that every Raqib build shares.
 *
 * Two builds come out of this:
 *
 *   dist/raqib.mjs    the ordinary single-file script, ESM
 *   dist/sea/*.cjs    the CommonJS bundle that becomes Raqib.exe
 *
 * They differ in two ways only: the module format, and which flavour of
 * `core/runtime` they use — the ordinary build can run the worker that
 * sits beside it, the executable has to write its embedded worker out first.
 */
import { readFileSync, existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');

const FONT_FILES = [
  ['bricolage', '@fontsource/bricolage-grotesque/files/bricolage-grotesque-latin-400-normal.woff2'],
  ['plexSans', '@fontsource/ibm-plex-sans/files/ibm-plex-sans-latin-400-normal.woff2'],
  ['plexSansMedium', '@fontsource/ibm-plex-sans/files/ibm-plex-sans-latin-500-normal.woff2'],
  ['plexMono', '@fontsource/ibm-plex-mono/files/ibm-plex-mono-latin-400-normal.woff2'],
  ['plexMonoMedium', '@fontsource/ibm-plex-mono/files/ibm-plex-mono-latin-500-normal.woff2'],
];

export function fontData() {
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

/** The built search worker, as source that can travel inside a bundle. */
export function workerSource() {
  const file = join(root, 'dist', 'searchWorker.mjs');
  if (!existsSync(file)) {
    throw new Error('missing dist/searchWorker.mjs — build the worker first');
  }
  return readFileSync(file, 'utf8');
}

/** Inline local assets (html/css/js) and the base64 font payload. */
export const inlineAssets = {
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

/**
 * Inline the search worker as source.
 *
 * A single-file executable has nothing beside it, so the worker has to
 * travel inside the bundle and be written out at run time.
 */
export const inlineWorker = {
  name: 'raqib-inline-worker',
  setup(pluginBuild) {
    pluginBuild.onResolve({ filter: /^virtual:worker$/ }, () => ({
      path: 'worker',
      namespace: 'raqib-worker',
    }));
    pluginBuild.onLoad({ filter: /.*/, namespace: 'raqib-worker' }, () => ({
      contents: `export const workerSource = ${JSON.stringify(workerSource())};`,
      loader: 'js',
    }));
  },
};

/**
 * Point `./runtime.js` at the flavour of the runtime this build needs.
 *
 * The ordinary build runs from a file and can use the worker that sits
 * beside it. The executable cannot, so it gets the flavour that writes the
 * embedded worker out to a temporary file instead.
 */
export const runtimeFlavour = (flavour) => ({
  name: 'raqib-runtime-flavour',
  setup(pluginBuild) {
    const files = { node: 'runtime.ts', sea: 'runtime.sea.ts' };
    const file = files[flavour];
    if (!file) throw new Error(`unknown runtime flavour: ${flavour}`);
    // The runtime is imported from inside `core` and from the entry point
    // beside it, so both spellings have to be caught. The target is worked
    // out from the project root, so the two spellings cannot drift apart.
    pluginBuild.onResolve({ filter: /^\.\/(core\/)?runtime\.js$/ }, () => ({
      path: resolve(root, 'src', 'core', file),
    }));
  },
});

/** The options every build shares. */
export function commonOptions({ format, runtime }) {
  return {
    bundle: true,
    platform: 'node',
    target: 'node20',
    format,
    logLevel: 'warning',
    legalComments: 'none',
    plugins: [inlineAssets, inlineWorker, runtimeFlavour(runtime)],
  };
}
