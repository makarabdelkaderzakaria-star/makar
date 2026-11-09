#!/usr/bin/env node
/**
 * Build a release bundle: the shipped file, the documentation, and the
 * checksums that say what was shipped.
 *
 *   node scripts/package-release.mjs [version]
 *
 * Two packages come out of this, because the two audiences unpack
 * differently:
 *
 *   raqib-<version>-<platform>-<arch>.tar.gz   the usual one
 *   raqib-<version>-windows.zip                for Windows, which has a
 *                                              built-in unzip and no
 *                                              built-in tar
 *
 * The output lands in release/ and is never committed: a release is an
 * artefact, not source.
 */
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { arch, platform } from 'node:os';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
const version = process.argv[2] ?? pkg.version;
const name = `raqib-${version}-${platform()}-${arch()}`;
const stage = join(root, 'release', name);

rmSync(join(root, 'release'), { recursive: true, force: true });
mkdirSync(stage, { recursive: true });

// 1. the shipped file
const binary = join(root, 'dist', 'raqib.mjs');
if (!existsSync(binary)) {
  console.error('raqib: dist/raqib.mjs is missing — run `npm run build` first');
  process.exit(1);
}
cpSync(binary, join(stage, 'raqib.mjs'));
cpSync(join(root, 'dist', 'searchWorker.mjs'), join(stage, 'searchWorker.mjs'));

// 2. a launcher, so the command has a name
writeFileSync(join(stage, 'raqib'), `#!/bin/sh
# Run Raqib from the folder it was unpacked into.
exec node "$(dirname "$0")/raqib.mjs" "$@"
`, 'utf8');

writeFileSync(join(stage, 'raqib.cmd'), `@echo off
rem Run Raqib from the folder it was unpacked into.
node "%~dp0raqib.mjs" %*
`, 'utf8');

// 3. the documents
mkdirSync(join(stage, 'docs'), { recursive: true });
for (const file of ['README.md', 'LICENSE', 'NOTICE', 'LIMITATIONS.md', 'CHANGELOG.md']) {
  cpSync(join(root, file), join(stage, file));
}
// The quick-start, in Arabic and English, for whoever opens the archive first.
cpSync(join(root, 'TRY-IT.md'), join(stage, 'TRY-IT.md'));
for (const file of ['ARCHITECTURE.md', 'MCP.md', 'COMPARISON.md', 'DESIGN.md', 'ROADMAP.md']) {
  cpSync(join(root, 'docs', file), join(stage, 'docs', file));
}

// 4. what this bundle proves, and what it does not
const binaryBytes = statSync(binary).size;
const buildInfo = `raqib ${version}
built: ${new Date().toISOString()}
built on: ${platform()} ${arch()}
node: ${process.version}
artifact: raqib.mjs (${binaryBytes} bytes) + searchWorker.mjs
runtime dependencies: none

The shipped file contains the MCP server, the command line, the local console
and the three typefaces it uses. It opens no socket, at any point, for any
reason. Running it requires Node ${pkg.engines.node} and nothing else.

raqib.mjs is the same file on every operating system: it is JavaScript, not a
compiled executable. The .cmd and the shell script next to it are launchers.

Checksums for this bundle are in SHA256SUMS. Verify them with:
  sha256sum -c SHA256SUMS          (Linux, macOS)
  certutil -hashfile raqib.mjs SHA256   (Windows)

Start here:
  node raqib.mjs --help
  node raqib.mjs doctor
`;
writeFileSync(join(stage, 'BUILD-INFO.txt'), buildInfo, 'utf8');

// 5. checksums
const files = [
  'raqib.mjs', 'searchWorker.mjs', 'raqib', 'raqib.cmd',
  'README.md', 'TRY-IT.md', 'LICENSE', 'NOTICE', 'LIMITATIONS.md', 'CHANGELOG.md', 'BUILD-INFO.txt',
];
const sums = files
  .map((file) => {
    const digest = createHash('sha256').update(readFileSync(join(stage, file))).digest('hex');
    return `${digest}  ${file}`;
  })
  .join('\n');
writeFileSync(join(stage, 'SHA256SUMS'), `${sums}\n`, 'utf8');

// 6. the tarball
const tarball = join(root, 'release', `${name}.tar.gz`);
execFileSync('tar', ['-czf', tarball, '-C', join(root, 'release'), name]);
const tarballBytes = statSync(tarball).size;
const tarballDigest = createHash('sha256').update(readFileSync(tarball)).digest('hex');

// 7. the zip, for Windows
// `zip` may not be installed everywhere; node's own zip writer is not in
// core either, so the archive is built by hand when the tool is missing.
const zipName = `raqib-${version}-windows.zip`;
const zipPath = join(root, 'release', zipName);
const zipStage = join(root, 'release', `raqib-${version}-windows`);
rmSync(zipStage, { recursive: true, force: true });
cpSync(stage, zipStage, { recursive: true });
rmSync(join(zipStage, 'docs'), { recursive: true });
try {
  execFileSync('zip', ['-qr', zipPath, `raqib-${version}-windows`], { cwd: join(root, 'release') });
} catch {
  console.warn('raqib: the "zip" command is missing — skipping the Windows archive');
}

console.log(`raqib: packaged ${name}`);
console.log(`  stage  : release/${name}`);
console.log(`  tarball: release/${name}.tar.gz (${(tarballBytes / 1024).toFixed(1)} KiB)`);
console.log(`  sha256 : ${tarballDigest}`);
if (existsSync(zipPath)) {
  const zipBytes = statSync(zipPath).size;
  const zipDigest = createHash('sha256').update(readFileSync(zipPath)).digest('hex');
  writeFileSync(join(root, 'release', 'SHA256SUMS'), `${tarballDigest}  ${name}.tar.gz\n${zipDigest}  ${zipName}\n`, 'utf8');
  console.log(`  zip    : release/${zipName} (${(zipBytes / 1024).toFixed(1)} KiB)`);
  console.log(`  sha256 : ${zipDigest}`);
}
