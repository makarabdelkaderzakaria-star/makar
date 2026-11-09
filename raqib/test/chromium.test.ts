import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { analyzeChromiumTree, chromiumTreeEvidence, identifyBrowser, browserIdentityEvidence, browserSearchPaths } from '../src/core/chromium.js';

async function braveTree(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'raqib-chromium-'));
  const files: Array<[string, string]> = [
    ['build/args/brave.gn', 'brave_use_ads_fingerprinting = true\nbrave_enable_tor = false\n'],
    ['components/brave_ads/core/fingerprinting/fingerprinting_controller.cc', 'void FingerprintingController::Enable() {}\n'],
    ['components/brave_ads/core/debouncing.cc', 'void DebouncingController::Debounce() {}\n'],
    ['components/brave_rewards/rewards_panel.cc', '\n'],
    ['components/brave_tor/tor_profile.cc', '\n'],
    ['chrome/browser/ui/webui/shields.cc', 'void ShieldsSettings::Load() {}\n'],
  ];
  for (const [rel, body] of files) {
    const target = join(dir, rel);
    await mkdir(join(target, '..'), { recursive: true });
    await writeFile(target, body, 'utf8');
  }
  return dir;
}

test('maps a Brave source tree', async () => {
  const dir = await braveTree();
  try {
    const analysis = await analyzeChromiumTree(dir);

    assert.equal(analysis.flavour, 'brave');
    assert.ok(analysis.evidence.length > 0, 'the flavour comes with evidence');

    const names = analysis.subsystems.map((s) => s.subsystem);
    assert.ok(names.includes('fingerprinting'));
    assert.ok(names.includes('debouncing'));
    assert.ok(names.includes('shields'));
    assert.ok(names.includes('rewards'));
    assert.ok(names.includes('tor'));

    const fingerprinting = analysis.subsystems.find((s) => s.subsystem === 'fingerprinting');
    assert.ok(fingerprinting?.files.some((f) => f.includes('fingerprinting_controller.cc')));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('reads the build arguments, including the ones in build/args', async () => {
  const dir = await braveTree();
  try {
    const analysis = await analyzeChromiumTree(dir);
    const names = analysis.buildArguments.map((a) => a.name);

    assert.ok(names.includes('brave_use_ads_fingerprinting'));
    assert.ok(names.includes('brave_enable_tor'));

    const arg = analysis.buildArguments.find((a) => a.name === 'brave_enable_tor');
    assert.equal(arg?.value, 'false');
    assert.equal(arg?.file, 'build/args/brave.gn');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('the chromium evidence names the gaps', async () => {
  const dir = await braveTree();
  try {
    const evidence = chromiumTreeEvidence(await analyzeChromiumTree(dir));
    assert.equal(evidence.kind, 'chromium-tree');
    assert.ok(evidence.facts.some((f) => f.label === 'tree.flavour' && f.value === 'brave'));
    assert.ok(evidence.locations.length > 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('identifies an installed browser from its own strings', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'raqib-browser-'));
  try {
    const header = 'Brave/1.62.126 Chrome/126.0.6478.126 brave_shields fingerprinting brave_rewards\n';
    const body = Buffer.concat([Buffer.from(header), Buffer.alloc(1024 * 1024, 0x41)]);
    await writeFile(join(dir, 'brave'), body);

    const identity = await identifyBrowser(dir);
    assert.equal(identity.product, 'Brave');
    assert.equal(identity.version, '1.62.126');
    assert.equal(identity.chromiumVersion, '126.0.6478');
    assert.ok(identity.features.includes('shields'));
    assert.ok(identity.features.includes('fingerprinting-protection'));

    const evidence = browserIdentityEvidence(identity);
    assert.ok(evidence.limitations.some((l) => l.includes('compiled out')));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('says so when a directory holds no browser', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'raqib-browser-'));
  try {
    await writeFile(join(dir, 'notes.txt'), 'nothing here', 'utf8');
    const identity = await identifyBrowser(dir);
    assert.equal(identity.product, null);
    assert.ok(identity.limitations.length > 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('the browser install list covers Windows, and says where', () => {
  const paths = browserSearchPaths();
  const labels = paths.map((p) => p.label);

  assert.ok(labels.some((l) => l.includes('Brave (Windows)')));
  assert.ok(labels.some((l) => l.includes('Chrome (Windows)')));
  assert.ok(labels.some((l) => l.includes('Edge (Windows)')));

  // Windows paths must look like Windows paths, with backslashes, whatever
  // machine Raqib happens to be running on.
  const brave = paths.find((p) => p.label === 'Brave (Windows)');
  assert.ok(brave);
  assert.match(brave!.path, /^C:\\Program Files\\BraveSoftware\\Brave-Browser$/);
  assert.ok(!brave!.path.includes('/'), 'a Windows path must not contain a forward slash');

  // The per-user entries exist only where %LOCALAPPDATA% exists.
  const perUser = paths.filter((p) => p.label.includes(', user'));
  assert.equal(perUser.length, process.env.LOCALAPPDATA ? 5 : 0);
});

test('reads a browser whose version resource keeps the name and the version apart', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'raqib-browser-'));
  try {
    // A Windows executable keeps ProductName and ProductVersion in separate
    // UTF-16 strings, and keeps them at the very end of the file. The
    // detector has to reach the end and put the two back together.
    const head = Buffer.from('x'.repeat(1024), 'utf8');
    const filler: Buffer[] = [head];
    for (let i = 0; i < 400; i += 1) {
      filler.push(Buffer.from(`some ordinary resource string number ${i} padding padding`, 'utf8'));
      filler.push(Buffer.from([0, 0, 0, 0]));
    }
    // Each string in a version resource is null-terminated.
    const utf16 = (text: string) => Buffer.from(`${text}\0`, 'utf16le');
    const resource = Buffer.concat([
      utf16('CompanyName'),
      utf16('The Brave Company'),
      utf16('FileDescription'),
      utf16('Brave Browser'),
      utf16('ProductName'),
      utf16('Brave'),
      utf16('ProductVersion'),
      utf16('1.101.38'),
      utf16('OriginalFilename'),
      utf16('brave.exe'),
    ]);
    // The detector only looks at files that look like an executable, so
    // the fixture has to be big enough to be taken seriously.
    filler.push(Buffer.alloc(1_200_000, 0x20));
    const exe = join(dir, 'brave.exe');
    await writeFile(exe, Buffer.concat([...filler, resource]));

    const identity = await identifyBrowser(dir);
    assert.equal(identity.product, 'Brave');
    assert.equal(identity.engine, 'Chromium');
    assert.equal(identity.version, '1.101.38');
    assert.ok(identity.executable?.endsWith('brave.exe'));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('the version resource is read even when the file is mostly noise', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'raqib-browser-'));
  try {
    // Sixty thousand strings before the version resource: enough to stop a
    // scan that gives up early.
    const parts: Buffer[] = [];
    for (let i = 0; i < 61000; i += 1) {
      parts.push(Buffer.from(`noise string ${i} with some padding to make it longer`, 'utf8'));
      parts.push(Buffer.from([0]));
    }
    const utf16 = (text: string) => Buffer.from(`${text}\0`, 'utf16le');
    parts.push(utf16('ProductName'));
    parts.push(utf16('Vivaldi'));
    parts.push(utf16('ProductVersion'));
    parts.push(utf16('7.5.3735.47'));
    const exe = join(dir, 'vivaldi.exe');
    await writeFile(exe, Buffer.concat(parts));

    const identity = await identifyBrowser(dir);
    assert.equal(identity.product, 'Vivaldi');
    assert.equal(identity.version, '7.5.3735.47');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
