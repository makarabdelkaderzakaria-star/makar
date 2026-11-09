import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanJsSource } from '../src/core/js.js';

test('finds imports, exports and requires', () => {
  const source = [
    "import path from 'node:path';",
    "import { join } from \"node:path\";",
    "export { helper } from './helper.js';",
    "const fs = require('fs');",
  ].join('\n');

  const scan = scanJsSource(source);

  assert.deepEqual(
    scan.imports.map((hit) => hit.value),
    ['node:path', 'node:path'],
  );
  assert.deepEqual(scan.exports.map((hit) => hit.value), ['./helper.js']);
  assert.deepEqual(scan.requires.map((hit) => hit.value), ['fs']);
});

test('ignores imports that only appear in comments or strings', () => {
  const source = [
    "// import 'from-a-comment'",
    "/* import 'from-a-block-comment' */",
    "const text = \"import 'from-a-string'\";",
    "const other = 'require(\"from-a-string\")';",
    "import 'real';",
  ].join('\n');

  const scan = scanJsSource(source);

  assert.deepEqual(scan.imports.map((hit) => hit.value), ['real']);
  assert.deepEqual(scan.requires.map((hit) => hit.value), []);
});

test('ignores a division operator that looks like a regular expression', () => {
  const source = 'const ratio = total / count;\nconst half = value / 2 / 3;\n';
  const scan = scanJsSource(source);
  assert.equal(scan.imports.length, 0);
  assert.equal(scan.requires.length, 0);
});

test('maps Electron IPC channels to their side', () => {
  const source = [
    "ipcMain.handle('feature:toggle', (_event, value) => value);",
    "ipcMain.on('feature:changed', () => {});",
    "const result = await ipcRenderer.invoke('feature:get', 1);",
    "ipcRenderer.send('feature:ping');",
    "contextBridge.exposeInMainWorld('bridge', api);",
  ].join('\n');

  const scan = scanJsSource(source);

  assert.deepEqual(scan.channels.handle, ['feature:toggle']);
  assert.deepEqual(scan.channels.on, ['feature:changed']);
  assert.deepEqual(scan.channels.invoke, ['feature:get']);
  assert.deepEqual(scan.channels.send, ['feature:ping']);
  assert.deepEqual(scan.channels.expose, ['bridge']);
});

test('reports webPreferences security switches', () => {
  const source = [
    'new BrowserWindow({',
    '  webPreferences: {',
    '    nodeIntegration: false,',
    '    contextIsolation: true,',
    '    sandbox: true,',
    '    preload: path.join(__dirname, "preload.js"),',
    '  },',
    '});',
  ].join('\n');

  const scan = scanJsSource(source);
  for (const key of ['nodeIntegration', 'contextIsolation', 'sandbox', 'preload']) {
    assert.ok(scan.webPreferences.includes(key), `${key} is detected`);
  }
});

test('finds source map references inside comments', () => {
  const scan = scanJsSource('//# sourceMappingURL=app.js.map\nconsole.log(1);\n');
  assert.deepEqual(scan.sourceMaps, ['app.js.map']);
});

test('reports line and column for each finding', () => {
  const source = "const a = 1;\nconst b = 2;\nimport 'late';\n";
  const scan = scanJsSource(source);
  const hit = scan.imports[0];
  assert.equal(hit.line, 3);
  assert.equal(hit.column, 1);
});

test('detects a framework from its import', () => {
  const scan = scanJsSource("import React from 'react';\nimport { render } from 'react-dom';\n");
  assert.ok(scan.frameworks.includes('react'));
});
