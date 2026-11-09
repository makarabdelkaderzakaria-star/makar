/**
 * The Evidence model.
 *
 * Every Raqib answer is an Evidence record: a stable identity, a human
 * summary, typed facts, the exact locations the facts came from, and — the
 * part that matters most — an explicit list of what was *not* proven.
 *
 * The identity is a content hash: the same target analysed twice produces the
 * same id, so an agent can compare two runs without diffing prose.
 */
import { nowIso, shortHash } from './util.js';

export type Confidence = 'certain' | 'likely' | 'unverified';

export interface SourceLocation {
  /** Absolute path of the file the fact came from. */
  file: string;
  /** 1-based line, when the fact is anchored to a line. */
  line?: number;
  /** 1-based column. */
  column?: number;
  /** Byte offset into the file, for binary facts. */
  offset?: number;
  /** Short note describing what the location holds. */
  note?: string;
}

export interface Fact {
  /** Stable machine label, e.g. "elf.machine". */
  label: string;
  /** Human value. */
  value: string;
  /** Optional longer explanation. */
  detail?: string;
  /** Where the fact was observed. */
  source?: SourceLocation;
  confidence?: Confidence;
}

export interface Metric {
  label: string;
  value: number;
  unit?: string;
}

export interface Evidence {
  /** Content-derived identity, stable across runs. */
  id: string;
  /** What kind of evidence this is: "elf", "pe", "js-application", … */
  kind: string;
  /** The subject the evidence is about. */
  subject: string;
  /** Tool version that produced it. */
  producer: string;
  /** ISO timestamp of the run. */
  generated_at: string;
  /** One-paragraph summary. */
  summary: string;
  facts: Fact[];
  locations: SourceLocation[];
  metrics: Metric[];
  /** Everything this run could not establish. */
  limitations: string[];
  /** Free-form structured payload for machine consumers. */
  data?: Record<string, unknown>;
}

export interface EvidenceInit {
  kind: string;
  subject: string;
  summary: string;
  /** Overrides the wall-clock stamp; the identity never depends on it. */
  generated_at?: string;
  producer?: string;
  facts?: Fact[];
  locations?: SourceLocation[];
  metrics?: Metric[];
  limitations?: string[];
  data?: Record<string, unknown>;
}

/** Build an Evidence record with a content-derived id. */
export function makeEvidence(init: EvidenceInit, producer = 'raqib/0.2.0'): Evidence {
  const facts = init.facts ?? [];
  const locations = init.locations ?? [];
  const metrics = init.metrics ?? [];
  const limitations = init.limitations ?? [];
  const generated_at = init.generated_at ?? nowIso();

  // The id covers the substance of the record, not the wall clock, so a
  // re-run of the same analysis keeps the same identity.
  const identity = JSON.stringify({
    kind: init.kind,
    subject: init.subject,
    summary: init.summary,
    facts: facts.map((f) => [f.label, f.value, f.source ?? null]),
    locations: locations.map((l) => [l.file, l.line ?? null, l.column ?? null, l.offset ?? null]),
    metrics: metrics.map((m) => [m.label, m.value, m.unit ?? null]),
    limitations,
  });

  return {
    id: `ev_${shortHash(identity)}`,
    kind: init.kind,
    subject: init.subject,
    producer,
    generated_at,
    summary: init.summary,
    facts,
    locations,
    metrics,
    limitations,
    data: init.data,
  };
}

/** Merge a set of limitations without duplicates, keeping the first order. */
export function mergeLimitations(...groups: (string[] | undefined)[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const group of groups) {
    for (const item of group ?? []) {
      if (!seen.has(item)) {
        seen.add(item);
        out.push(item);
      }
    }
  }
  return out;
}

export function fact(label: string, value: string | number | boolean, extra: Partial<Fact> = {}): Fact {
  return {
    label,
    value: typeof value === 'string' ? value : String(value),
    ...extra,
  };
}
