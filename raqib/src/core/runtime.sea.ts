/**
 * The single-file-executable flavour of the runtime.
 *
 * Inside a `Raqib.exe` there is no file beside the code — the whole program
 * is one blob — so the embedded worker is always written out to a temporary
 * file and run from there.
 *
 * `import.meta` does not exist in the CommonJS bundle that a single
 * executable is built from, which is why this is a separate module rather
 * than a branch inside `runtime.ts`.
 */
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { workerSource } from 'virtual:worker';

let materialised: string | null = null;

/** Write the embedded worker to a temporary file and return its path. */
export function materialiseWorker(): string {
  if (materialised) return materialised;
  const dir = mkdtempSync(join(tmpdir(), 'raqib-'));
  const file = join(dir, 'searchWorker.mjs');
  writeFileSync(file, workerSource, 'utf8');
  materialised = file;
  return file;
}

/** There is never a sibling file inside an executable. */
export function siblingWorker(): string {
  return '';
}

/** The path the search worker should be spawned from. */
export function resolveWorkerScript(): string {
  return materialiseWorker();
}
