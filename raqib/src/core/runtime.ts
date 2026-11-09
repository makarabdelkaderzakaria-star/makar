/**
 * Where the search worker lives.
 *
 * In the normal build the worker is a file sitting beside the shipped
 * script, and that is where it is run from.
 *
 * In a single-file executable there is no such file: the executable is one
 * blob with nothing beside it. So the worker's source is embedded in the
 * bundle, and the first time the worker is needed it is written out to a
 * temporary file and run from there.
 *
 * This module exists so that the *search engine* never has to know which of
 * the two worlds it is running in. It asks for a script path and gets one.
 */
import { existsSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { workerSource } from 'virtual:worker';

let materialised: string | null = null;

/**
 * Write the embedded worker to a temporary file and return its path.
 *
 * The directory is created per process and the name carries the worker's
 * content hash, so two Raqib processes never fight over the same file.
 */
export function materialiseWorker(): string {
  if (materialised) return materialised;
  const dir = mkdtempSync(join(tmpdir(), 'raqib-'));
  const file = join(dir, 'searchWorker.mjs');
  writeFileSync(file, workerSource, 'utf8');
  materialised = file;
  return file;
}

/** The worker script that sits beside this module, if there is one. */
export function siblingWorker(): string {
  const beside = join(dirname(fileURLToPath(import.meta.url)), 'searchWorker.mjs');
  return existsSync(beside) ? beside : '';
}

/**
 * The path the search worker should be spawned from.
 *
 * The sibling file wins when it is there, because running from a file on
 * disk is faster and easier to debug. Otherwise the embedded copy is
 * written out and used.
 */
export function resolveWorkerScript(): string {
  const beside = siblingWorker();
  if (beside) return beside;
  return materialiseWorker();
}
