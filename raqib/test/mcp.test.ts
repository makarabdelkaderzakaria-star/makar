import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { RaqibMcpServer, TOOLS, renderEvidenceText } from '../src/mcp/server.js';
import { makeEvidence } from '../src/core/evidence.js';

test('initialize negotiates a protocol version and advertises tools', async () => {
  const server = new RaqibMcpServer();
  const response = await server.handle({
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: { protocolVersion: '2024-11-05', clientInfo: { name: 'test', version: '1' } },
  });

  assert.ok(response);
  const result = response.result as Record<string, unknown>;
  assert.equal(result.protocolVersion, '2024-11-05');
  assert.equal((result.serverInfo as Record<string, string>).name, 'raqib');
  assert.ok((result.capabilities as Record<string, unknown>).tools);
});

test('initialize falls back to the current protocol for an unknown request', async () => {
  const server = new RaqibMcpServer();
  const response = await server.handle({
    jsonrpc: '2.0', id: 2, method: 'initialize', params: { protocolVersion: '1999-01-01' },
  });
  const result = response?.result as Record<string, unknown>;
  assert.equal(result.protocolVersion, '2025-06-18');
});

test('tools/list returns every tool with an input schema', async () => {
  const server = new RaqibMcpServer();
  const response = await server.handle({ jsonrpc: '2.0', id: 3, method: 'tools/list' });
  const result = response?.result as { tools: Array<{ name: string; inputSchema: Record<string, unknown> }> };

  assert.equal(result.tools.length, TOOLS.length);
  for (const tool of result.tools) {
    assert.ok(tool.name.length > 0);
    assert.equal(tool.inputSchema.type, 'object');
    assert.ok(Array.isArray(tool.inputSchema.required));
  }
});

test('notifications produce no response', async () => {
  const server = new RaqibMcpServer();
  const response = await server.handle({ jsonrpc: '2.0', method: 'notifications/initialized' });
  assert.equal(response, null);
});

test('an unknown method is an error, not a crash', async () => {
  const server = new RaqibMcpServer();
  const response = await server.handle({ jsonrpc: '2.0', id: 4, method: 'does/not/exist' });
  assert.ok(response?.error);
  assert.match(response!.error!.message, /unknown method/);
});

test('a tool call returns evidence in both channels', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'raqib-mcp-'));
  try {
    await mkdir(join(dir, 'src'), { recursive: true });
    await writeFile(join(dir, 'package.json'), JSON.stringify({ name: 'demo', version: '1.2.3', main: 'src/main.js' }), 'utf8');
    await writeFile(join(dir, 'src', 'main.js'), "ipcMain.handle('demo:ping', () => 'pong');\n", 'utf8');

    const server = new RaqibMcpServer();
    const response = await server.handle({
      jsonrpc: '2.0',
      id: 5,
      method: 'tools/call',
      params: { name: 'analyze_js_application', arguments: { path: dir } },
    });

    const result = response?.result as {
      content: Array<{ type: string; text: string }>;
      structuredContent: { evidence_id: string; normalized_result: { kind: string } };
    };

    assert.equal(result.content[0].type, 'text');
    assert.match(result.content[0].text, /js-application/);
    assert.equal(result.structuredContent.normalized_result.kind, 'js-application');
    assert.match(result.structuredContent.evidence_id, /^ev_[0-9a-f]{16}$/);

    // The evidence can be fetched back by id.
    const fetch = await server.handle({
      jsonrpc: '2.0', id: 6, method: 'tools/call',
      params: { name: 'get_evidence', arguments: { id: result.structuredContent.evidence_id } },
    });
    assert.ok((fetch?.result as { content: Array<{ text: string }> }).content[0].text.includes('demo'));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('a missing argument is refused with a clear message', async () => {
  const server = new RaqibMcpServer();
  const response = await server.handle({
    jsonrpc: '2.0', id: 7, method: 'tools/call',
    params: { name: 'search_code', arguments: { path: '/tmp' } },
  });
  assert.ok(response?.error);
  assert.match(response!.error!.message, /pattern/);
});

test('the evidence identity is stable for the same content', () => {
  const build = () => makeEvidence({
    kind: 'test', subject: '/x', summary: 'same',
    facts: [{ label: 'a', value: 'b' }],
  });
  assert.equal(build().id, build().id);

  const different = makeEvidence({ kind: 'test', subject: '/x', summary: 'different' });
  assert.notEqual(build().id, different.id);
});

test('the text rendering names the gaps', () => {
  const evidence = makeEvidence({
    kind: 'test',
    subject: '/x',
    summary: 'summary',
    facts: [{ label: 'a', value: 'b' }],
    limitations: ['this was not proven'],
  });
  const text = renderEvidenceText(evidence);
  assert.match(text, /## Not proven/);
  assert.match(text, /this was not proven/);
});
