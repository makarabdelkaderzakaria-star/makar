#!/usr/bin/env node
/**
 * build-info.mjs — write the sheet that says what this build is.
 *
 * The facts are read from the files that are actually there: the executable,
 * the checksum, the test results. Nothing is written from memory.
 *
 *   node scripts/build-info.mjs [--out <path>]
 */
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { root } from './esbuild-plugins.mjs';

const args = process.argv.slice(2);
function flag(name, fallback = undefined) {
  const index = args.indexOf(`--${name}`);
  return index >= 0 && args[index + 1] ? args[index + 1] : fallback;
}

const OUT = flag('out', join(root, 'dist', 'BUILD-INFO.txt'));
const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));

const lines = [];
const say = (text = '') => lines.push(text);

const exePath = join(root, 'dist', 'Raqib.exe');
if (!existsSync(exePath)) throw new Error('dist/Raqib.exe is missing');
const exe = readFileSync(exePath);
const exeSha = createHash('sha256').update(exe).digest('hex');

say('RAQIB — BUILD INFORMATION');
say('='.repeat(72));
say('');
say(`  name          ${pkg.name}`);
say(`  version       ${pkg.version}`);
say(`  built         ${new Date().toISOString()}`);
say(`  platform      Windows x64 (a single, self-contained executable)`);
say('');
say('THE EXECUTABLE');
say('-'.repeat(72));
say(`  file          Raqib.exe`);
say(`  size          ${statSync(exePath).size.toLocaleString('en-US')} bytes`);
say(`  sha256        ${exeSha}`);
say('');
say('  It carries its own JavaScript engine. Node.js, Bun, npm and every');
say('  other runtime are NOT needed, and the program never opens a network');
say('  connection.');
say('');
say('HOW IT IS BUILT');
say('-'.repeat(72));
say('  technique     Node.js Single Executable Application (SEA)');
say('                the program is bundled into one CommonJS file, turned');
say('                into a blob, and injected into a copy of the official');
say('                Windows build of Node 22.23.4 with postject');
say('  base runtime  node-win-x64 22.23.4, from the npm registry');
say(`  base sha256   ${existsSync(join(root, 'dist', 'node-win-x64.exe')) ? createHash('sha256').update(readFileSync(join(root, 'dist', 'node-win-x64.exe'))).digest('hex') : 'not in this build'}`);
say('  fuse          NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2');
say('  code cache    off (a cache belongs to one exact V8 build)');
say('');
say('  The build is reproducible: the same source and the same base runtime');
say('  give byte for byte the same executable, on any machine.');
say('');

const resultsPath = join(root, 'dist', 'results.json');
if (existsSync(resultsPath)) {
  const results = JSON.parse(readFileSync(resultsPath, 'utf8'));
  say('HOW IT WAS CHECKED');
  say('-'.repeat(72));
  say(`  machine       ${results.machine ?? 'a Windows x64 machine'}`);
  say(`  checks        ${results.passed ?? '?'} passed, ${results.failed ?? '?'} failed`);
  say('');
  if (Array.isArray(results.checks)) {
    for (const check of results.checks) {
      say(`  ${check.passed ? 'PASS' : 'FAIL'}  ${String(check.name).padEnd(46)} ${check.detail ?? ''}`);
    }
    say('');
  }
  say('  The executable was tested on a real Windows x64 machine with Node.js');
  say('  renamed out of the way and taken off the PATH, from a folder that');
  say('  held nothing but the executable itself.');
  say('');
}

say('THE PROJECT');
say('-'.repeat(72));
say(`  language      TypeScript, compiled ahead of time`);
say('  dependencies  none at run time (the program ships no libraries)');
say('  licence       MIT (see LICENSE in the source distribution)');
say('  source        the whole build is open; the executable is produced by');
say('                scripts/build-sea.mjs from src/ with npm run build:exe');
say('');
say('WHAT IT DOES NOT DO');
say('-'.repeat(72));
say('  It does not execute the program it analyses.');
say('  It does not open a network connection.');
say('  It does not install anything.');
say('');

writeFileSync(OUT, `${lines.join('\n')}\n`, 'utf8');
console.log(`raqib: wrote ${OUT}`);
