#!/usr/bin/env node
/**
 * Build the fixtures that the Windows executable is tested against.
 *
 * These are real files, not stubs: a genuine ASAR archive, a genuine source
 * map, a genuine package manifest, two versions of an application to
 * compare, and a tree large enough to make the search engine reach for its
 * worker threads.
 *
 *   node scripts/make-fixtures.mjs <directory>
 *
 * This runs before Node is removed from the test machine; the executable is
 * then measured against what it leaves behind.
 */
import { build } from 'esbuild';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const out = resolve(process.argv[2] ?? join(root, 'dist', 'fixtures'));

rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });

// ---------------------------------------------------------------------------
// a genuine ASAR archive, built by the same code the test suite uses
// ---------------------------------------------------------------------------

const asarModule = join(tmpdir(), `raqib-asar-fixture-${process.pid}.mjs`);
await build({
  entryPoints: [join(root, 'test/fixtures/asar.ts')],
  outfile: asarModule,
  bundle: true,
  platform: 'node',
  format: 'esm',
  logLevel: 'warning',
});
const { buildAsar } = await import(`file://${asarModule}`);
buildAsar(join(out, 'app.asar'), {});

// ---------------------------------------------------------------------------
// a genuine source map
// ---------------------------------------------------------------------------

const bundle = [
  'function start(options) {',
  '  const banner = "raqib";',
  '  return `${banner} started (verbose=${options.verbose})`;',
  '}',
  'function stop() {',
  '}',
  'console.log(start({ verbose: true }));',
  'stop();',
  '//# sourceMappingURL=bundle.js.map',
  '',
].join('\n');

const sourceMap = {
  version: 3,
  file: 'bundle.js',
  sources: ['../src/app.ts', '../src/main.ts'],
  sourcesContent: [
    'export interface Options { verbose: boolean }\n\nexport function start(options: Options): string {\n  const banner = "raqib";\n  return `${banner} started`;\n}\n',
    'import { start, stop } from "./app.js";\nconsole.log(start({ verbose: true }));\nstop();\n',
  ],
  names: [],
  // line 1 -> app.ts:1, line 2 -> app.ts:3, line 3 -> app.ts:4, line 7 -> main.ts:2
  mappings: 'AAAA;AACA;AACA;ACAA',
};

writeFileSync(join(out, 'bundle.js'), bundle, 'utf8');
writeFileSync(join(out, 'bundle.js.map'), JSON.stringify(sourceMap), 'utf8');

// ---------------------------------------------------------------------------
// two versions of an application, to compare
// ---------------------------------------------------------------------------

function application(dir, version, channels) {
  mkdirSync(join(out, dir, 'src'), { recursive: true });
  writeFileSync(join(out, dir, 'package.json'), JSON.stringify({
    name: 'fixture-app',
    version,
    main: 'src/main.js',
    scripts: { start: 'node src/main.js' },
    dependencies: { electron: '31.0.0' },
  }, null, 2), 'utf8');
  writeFileSync(join(out, dir, 'src', 'main.js'),
    channels.map((c) => `ipcMain.handle('${c}', () => 1);`).join('\n') + '\n', 'utf8');
}

application('old-build', '1.0.0', ['alpha', 'beta']);
application('new-build', '1.1.0', ['alpha', 'beta', 'gamma']);

// ---------------------------------------------------------------------------
// a package manifest on its own
// ---------------------------------------------------------------------------

writeFileSync(join(out, 'package.json'), JSON.stringify({
  name: 'fixture-manifest',
  version: '2.3.1',
  description: 'a manifest for the executable to read',
  main: 'src/main.js',
  scripts: { build: 'tsc -p .' },
  dependencies: { electron: '31.0.0', 'lodash.merge': '^4.6.2' },
  devDependencies: { typescript: '5.7.2' },
  engines: { node: '>=20' },
  build: { electronVersion: '31.0.0' },
}, null, 2), 'utf8');

// ---------------------------------------------------------------------------
// a tree large enough to make the search engine use its worker threads
// ---------------------------------------------------------------------------

const big = join(out, 'big-tree');
mkdirSync(big, { recursive: true });
const TOTAL = 1500;
for (let i = 0; i < TOTAL; i += 1) {
  const dir = join(big, `dir-${Math.floor(i / 100)}`);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, `file-${i}.txt`),
    `line one of file ${i}\nneedle-${i % 7 === 0 ? 'FOUND' : 'ordinary'} content here\n`, 'utf8');
}
writeFileSync(join(big, 'needle-here.txt'), 'needle-FOUND at the top level\n', 'utf8');

// ---------------------------------------------------------------------------

console.log(`raqib: fixtures written to ${out}`);
console.log(`  app.asar, bundle.js + bundle.js.map, package.json, old-build/, new-build/, big-tree/ (${TOTAL} files)`);
