import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { analyzeChromiumTree, chromiumTreeEvidence, identifyBrowser, browserIdentityEvidence } from '../src/core/chromium.js';

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
