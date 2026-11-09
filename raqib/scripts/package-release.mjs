#!/usr/bin/env node
/**
 * Build a release bundle: the shipped file, the documentation, and the
 * checksums that say what was shipped.
 *
 *   node scripts/package-release.mjs [version]
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

// 2. the documents
mkdirSync(join(stage, 'docs'), { recursive: true });
for (const file of ['README.md', 'LICENSE', 'NOTICE', 'LIMITATIONS.md', 'CHANGELOG.md']) {
  cpSync(join(root, file), join(stage, file));
}
for (const file of ['ARCHITECTURE.md', 'MCP.md', 'COMPARISON.md', 'DESIGN.md', 'ROADMAP.md']) {
  cpSync(join(root, 'docs', file), join(stage, 'docs', file));
}

// 3. what this bundle proves, and what it does not
const binaryBytes = statSync(binary).size;
const buildInfo = `raqib ${version}
built: ${new Date().toISOString()}
platform: ${platform()} ${arch()}
node: ${process.version}
artifact: raqib.mjs (${binaryBytes} bytes) + searchWorker.mjs
runtime dependencies: none

The shipped file contains the MCP server, the command line, the local console
and the three typefaces it uses. It opens no socket, at any point, for any
reason. Running it requires Node ${pkg.engines.node} and nothing else.

Checksums for this bundle are in SHA256SUMS. Verify them with:
  sha256sum -c SHA256SUMS
`;
writeFileSync(join(stage, 'BUILD-INFO.txt'), buildInfo, 'utf8');

// 4. checksums
const files = ['raqib.mjs', 'searchWorker.mjs', 'README.md', 'LICENSE', 'NOTICE', 'LIMITATIONS.md', 'CHANGELOG.md', 'BUILD-INFO.txt'];
const sums = files
  .map((file) => {
    const digest = createHash('sha256').update(readFileSync(join(stage, file))).digest('hex');
    return `${digest}  ${file}`;
  })
  .join('\n');
writeFileSync(join(stage, 'SHA256SUMS'), `${sums}\n`, 'utf8');

// 5. the archive
const tarball = join(root, 'release', `${name}.tar.gz`);
execFileSync('tar', ['-czf', tarball, '-C', join(root, 'release'), name]);
const tarballBytes = statSync(tarball).size;
const tarballDigest = createHash('sha256').update(readFileSync(tarball)).digest('hex');
writeFileSync(join(root, 'release', 'SHA256SUMS'), `${tarballDigest}  ${name}.tar.gz\n`, 'utf8');

console.log(`raqib: packaged ${name}`);
console.log(`  stage  : release/${name}`);
console.log(`  tarball: release/${name}.tar.gz (${(tarballBytes / 1024).toFixed(1)} KiB)`);
console.log(`  sha256 : ${tarballDigest}`);
