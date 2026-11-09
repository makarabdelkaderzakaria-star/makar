/**
 * The local analysis console.
 *
 * A plain `node:http` server: no framework, no bundler at runtime, no
 * outbound requests. The interface is inlined into the binary, so the
 * console works on a machine with no network at all.
 */
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { join, resolve, extname } from 'node:path';
import { searchTree } from '../core/search.js';
import { analyzeTarget, type TargetKind } from '../core/analyze.js';
import type { Evidence } from '../core/evidence.js';
import uiHtml from './ui/index.html';
import uiCss from './ui/app.css';
import uiJs from './ui/app.ui.js';
import { fonts } from 'virtual:fonts';

const VERSION = '0.2.0';

const FONT_FACES = `
@font-face{font-family:'Bricolage';src:url(data:font/woff2;base64,${fonts.bricolage}) format('woff2');font-weight:200 800;font-display:swap;}
@font-face{font-family:'Plex Sans';src:url(data:font/woff2;base64,${fonts.plexSans}) format('woff2');font-weight:400;font-display:swap;}
@font-face{font-family:'Plex Sans';src:url(data:font/woff2;base64,${fonts.plexSansMedium}) format('woff2');font-weight:500 700;font-display:swap;}
@font-face{font-family:'Plex Mono';src:url(data:font/woff2;base64,${fonts.plexMono}) format('woff2');font-weight:400;font-display:swap;}
@font-face{font-family:'Plex Mono';src:url(data:font/woff2;base64,${fonts.plexMonoMedium}) format('woff2');font-weight:500 700;font-display:swap;}
`;

export interface ConsoleOptions {
  port?: number;
  host?: string;
}

export interface ConsoleServer {
  url: string;
  close: () => Promise<void>;
}

/** Start the console. */
export async function startConsole(options: ConsoleOptions = {}): Promise<ConsoleServer> {
  const host = options.host ?? '127.0.0.1';
  const port = options.port ?? 8787;

  const server = createServer((request, response) => {
    handle(request, response).catch((error: unknown) => {
      const message = error instanceof Error ? error.message : String(error);
      sendJson(response, 500, { error: message });
    });
  });

  await new Promise<void>((resolvePromise, rejectPromise) => {
    server.once('error', rejectPromise);
    server.listen(port, host, () => resolvePromise());
  });

  const address = server.address();
  const actualPort = typeof address === 'object' && address ? address.port : port;
  const displayHost = host === '0.0.0.0' ? '127.0.0.1' : host;

  return {
    url: `http://${displayHost}:${actualPort}`,
    close: () => new Promise<void>((resolvePromise) => server.close(() => resolvePromise())),
  };
}

async function handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
  const url = new URL(request.url ?? '/', 'http://localhost');
  const path = url.pathname;

  if (request.method === 'GET') {
    switch (path) {
      case '/':
        return sendText(response, 200, 'text/html; charset=utf-8', uiHtml);
      case '/app.css':
        return sendText(response, 200, 'text/css; charset=utf-8', uiCss.replace('/*__FONTS__*/', FONT_FACES));
      case '/app.js':
        return sendText(response, 200, 'text/javascript; charset=utf-8', uiJs);
      case '/api/health':
        return sendJson(response, 200, { ok: true, version: VERSION, offline: true });
      default:
        return sendJson(response, 404, { error: 'not found' });
    }
  }

  if (request.method === 'POST') {
    const body = await readBody(request);
    let payload: Record<string, unknown>;
    try {
      payload = JSON.parse(body || '{}') as Record<string, unknown>;
    } catch {
      return sendJson(response, 400, { error: 'invalid JSON body' });
    }

    try {
      switch (path) {
        case '/api/analyze': {
          const evidence = await analyzePath(payload);
          return sendJson(response, 200, { evidence });
        }
        case '/api/search': {
          const result = await searchTree(String(payload.path ?? ''), {
            pattern: String(payload.pattern ?? ''),
            regex: Boolean(payload.regex),
            caseSensitive: Boolean(payload.caseSensitive),
            maxResults: Number(payload.maxResults ?? 200),
            contextLines: Number(payload.contextLines ?? 0),
          });
          return sendJson(response, 200, { result });
        }
        case '/api/read': {
          const target = resolve(String(payload.path ?? ''));
          const info = await stat(target);
          if (info.size > 2 * 1024 * 1024) {
            return sendJson(response, 413, { error: 'file is larger than 2 MiB' });
          }
          const buffer = await readFile(target);
          return sendJson(response, 200, { path: target, bytes: info.size, text: buffer.toString('utf8').slice(0, 400000) });
        }
        default:
          return sendJson(response, 404, { error: 'not found' });
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return sendJson(response, 400, { error: message });
    }
  }

  return sendJson(response, 405, { error: 'method not allowed' });
}

/** Dispatch an analysis request by path type, or by an explicit kind. */
async function analyzePath(payload: Record<string, unknown>): Promise<Evidence> {
  const raw = String(payload.path ?? '').trim();
  if (!raw) throw new Error('a path is required');
  const target = resolve(raw);
  const kind = String(payload.kind ?? 'auto') as TargetKind;
  return analyzeTarget(target, kind);
}

function readBody(request: IncomingMessage): Promise<string> {
  return new Promise((resolvePromise, rejectPromise) => {
    const chunks: Buffer[] = [];
    let size = 0;
    request.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > 8 * 1024 * 1024) {
        rejectPromise(new Error('request body is too large'));
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });
    request.on('end', () => resolvePromise(Buffer.concat(chunks).toString('utf8')));
    request.on('error', rejectPromise);
  });
}

function sendJson(response: ServerResponse, status: number, payload: unknown): void {
  const body = JSON.stringify(payload);
  response.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body),
    'cache-control': 'no-store',
  });
  response.end(body);
}

function sendText(response: ServerResponse, status: number, type: string, body: string): void {
  response.writeHead(status, {
    'content-type': type,
    'content-length': Buffer.byteLength(body),
    'cache-control': 'no-store',
  });
  response.end(body);
}

export { join };
