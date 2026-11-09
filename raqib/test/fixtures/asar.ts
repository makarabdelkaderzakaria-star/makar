/** Build a genuine ASAR archive on disk so the reader can be tested. */
import { Buffer } from 'node:buffer';
import { writeFileSync } from 'node:fs';

export interface AsarFixture {
  files: Record<string, string>;
  path: string;
}

/**
 * The ASAR header is two nested pickles: a size pickle that says how long
 * the header pickle is, and the header pickle that carries the JSON tree.
 */
export function buildAsar(path: string, files: Record<string, string>): AsarFixture {
  const tree: Record<string, unknown> = { files: {} };
  const payload: Buffer[] = [];
  let offset = 0;

  const add = (node: Record<string, unknown>, name: string, contents: string) => {
    const buffer = Buffer.from(contents, 'utf8');
    (node.files as Record<string, unknown>)[name] = {
      size: buffer.length,
      offset: String(offset),
    };
    payload.push(buffer);
    offset += buffer.length;
  };

  const root = tree.files as Record<string, unknown>;
  const app: Record<string, unknown> = { files: {} };
  root['app'] = app;
  add(app, 'main.js', 'const { app } = require("electron");\napp.on("ready", () => {});\n');

  const nested: Record<string, unknown> = { files: {} };
  (app.files as Record<string, unknown>)['lib'] = nested;
  add(nested as any, 'util.js', 'export const answer = 42;\n');

  const json = Buffer.from(JSON.stringify(tree), 'utf8');
  const padding = (4 - (json.length % 4)) % 4;
  const payloadLength = 4 + json.length + padding;
  const headerSize = 4 + payloadLength;

  const header = Buffer.alloc(8 + headerSize);
  header.writeUInt32LE(4, 0);            // size pickle payload length
  header.writeUInt32LE(headerSize, 4);  // header pickle size
  header.writeUInt32LE(payloadLength, 8);
  header.writeUInt32LE(json.length, 12);
  json.copy(header, 16);

  const file = Buffer.concat([header, ...payload]);
  writeFileSync(path, file);
  return { files, path };
}
