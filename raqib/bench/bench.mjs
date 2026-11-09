#!/usr/bin/env node
/**
 * Raqib's own benchmark.
 *
 * Everything here is measured on the machine you run it on; the script
 * prints the machine it ran on so the numbers can be read in context.
 *
 *   node bench/bench.mjs [target-directory]
 */
import { spawnSync } from 'node:child_process';
import { statSync, readdirSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { cpus, totalmem, platform, release } from 'node:os';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');
const binary = join(root, 'dist', 'raqib.mjs');
const target = process.argv[2] ?? root;

function timeSync(label, args, options = {}) {
  const runs = options.runs ?? 5;
  const samples = [];
  for (let i = 0; i < runs; i += 1) {
    const started = process.hrtime.bigint();
    const result = spawnSync(process.execPath, [binary, ...args], {
      encoding: 'utf8',
      maxBuffer: 128 * 1024 * 1024,
    });
    const elapsed = Number(process.hrtime.bigint() - started) / 1e6;
    if (result.status !== 0) {
      console.error(`${label} failed: ${result.stderr}`);
      process.exit(1);
    }
    samples.push(elapsed);
  }
  samples.sort((a, b) => a - b);
  return {
    label,
    median: samples[Math.floor(samples.length / 2)],
    min: samples[0],
    max: samples[samples.length - 1],
    runs,
  };
}

/** A synthetic tree with a known shape, so the numbers are comparable. */
function buildFixture(rootDir, files = 2000) {
  rmSync(rootDir, { recursive: true, force: true });
  mkdirSync(join(rootDir, 'src'), { recursive: true });
  const lines = [];
  for (let i = 0; i < 400; i += 1) {
    lines.push(`export function handler${i}(input) { return input + ${i}; }`);
  }
  const body = lines.join('\n');
  for (let i = 0; i < files; i += 1) {
    const file = join(rootDir, 'src', `module${i}.ts`);
    writeFileSync(file, `${body}\n// marker: fixture\n`);
  }
  return rootDir;
}

const fixture = buildFixture(join(rootDirSafe(), 'raqib-bench-fixture'));

function rootDirSafe() {
  return join(process.env.TMPDIR ?? '/tmp', 'raqib-bench');
}

const results = [];

console.log('raqib benchmark');
console.log(`  machine : ${platform()} ${release()} · ${cpus().length} cores · ${(totalmem() / 1024 ** 3).toFixed(1)} GiB`);
console.log(`  runtime : ${process.version}`);
console.log(`  binary  : ${(statSync(binary).size / 1024).toFixed(1)} KiB, single file, zero runtime dependencies`);
console.log('');

const startup = timeSync('cold start (version)', ['version']);
results.push(startup);
console.log(`  cold start                 ${startup.median.toFixed(0).padStart(6)} ms   (min ${startup.min.toFixed(0)} ms)`);

const elf = timeSync('inspect /bin/ls', ['elf', '/bin/ls']);
results.push(elf);
console.log(`  ELF analysis               ${elf.median.toFixed(0).padStart(6)} ms`);

const index = timeSync('index fixture tree', ['index', fixture, '--json']);
results.push(index);
console.log(`  index ${countFiles(fixture)} files        ${index.median.toFixed(0).padStart(6)} ms`);

const search = timeSync('search fixture tree', ['search', fixture, 'handler137', '--json']);
results.push(search);
console.log(`  search fixture tree        ${search.median.toFixed(0).padStart(6)} ms`);

const js = timeSync('analyse js app', ['js', join(root, 'test'), '--json']);
results.push(js);
console.log(`  JS application analysis    ${js.median.toFixed(0).padStart(6)} ms`);

const bytes = readdirSync(join(root, 'dist'));
console.log('');
console.log(`  dist/: ${bytes.join(', ')}`);
console.log(`  shipped artifact: ${(statSync(binary).size / 1024).toFixed(1)} KiB (fonts, interface and server included)`);

writeFileSync(join(root, 'bench', 'results.json'), `${JSON.stringify({
  machine: { platform: platform(), release: release(), cores: cpus().length, node: process.version },
  binaryBytes: statSync(binary).size,
  results,
}, null, 2)}\n`);

rmSync(fixture, { recursive: true, force: true });

function countFiles(dir) {
  let total = 0;
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) total += countFiles(join(dir, entry.name));
    else total += 1;
  }
  return total;
}
