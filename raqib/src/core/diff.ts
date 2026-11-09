/**
 * Evidence diffing.
 *
 * Two runs of the same tool over two versions of the same thing are easy to
 * compare by eye and impossible to compare by hand. This compares two
 * Evidence records field by field and says exactly what moved.
 */
import { makeEvidence, type Evidence, type Fact, type SourceLocation } from './evidence.js';

export interface FactChange {
  label: string;
  before: string;
  after: string;
}

export interface EvidenceDiff {
  leftId: string;
  rightId: string;
  identical: boolean;
  facts: {
    added: Fact[];
    removed: Fact[];
    changed: FactChange[];
  };
  locations: {
    added: SourceLocation[];
    removed: SourceLocation[];
  };
  limitations: {
    added: string[];
    removed: string[];
  };
  summary: string;
}

function factKey(fact: Fact): string {
  return fact.label;
}

function locationKey(location: SourceLocation): string {
  return `${location.file}:${location.line ?? ''}:${location.column ?? ''}`;
}

/** Compare two Evidence records. */
export function diffEvidence(left: Evidence, right: Evidence): EvidenceDiff {
  const leftFacts = new Map(left.facts.map((f) => [factKey(f), f]));
  const rightFacts = new Map(right.facts.map((f) => [factKey(f), f]));

  const added: Fact[] = [];
  const removed: Fact[] = [];
  const changed: FactChange[] = [];

  for (const [label, fact] of rightFacts) {
    const before = leftFacts.get(label);
    if (!before) {
      added.push(fact);
    } else if (before.value !== fact.value) {
      changed.push({ label, before: before.value, after: fact.value });
    }
  }
  for (const [label, fact] of leftFacts) {
    if (!rightFacts.has(label)) removed.push(fact);
  }

  const leftLocations = new Map(left.locations.map((l) => [locationKey(l), l]));
  const rightLocations = new Map(right.locations.map((l) => [locationKey(l), l]));
  const locationsAdded = [...rightLocations.values()].filter((l) => !leftLocations.has(locationKey(l)));
  const locationsRemoved = [...leftLocations.values()].filter((l) => !rightLocations.has(locationKey(l)));

  const leftLimitations = new Set(left.limitations);
  const rightLimitations = new Set(right.limitations);
  const limitationsAdded = [...rightLimitations].filter((l) => !leftLimitations.has(l));
  const limitationsRemoved = [...leftLimitations].filter((l) => !rightLimitations.has(l));

  const identical = added.length === 0 && removed.length === 0 && changed.length === 0
    && locationsAdded.length === 0 && locationsRemoved.length === 0
    && limitationsAdded.length === 0 && limitationsRemoved.length === 0;

  const summary = identical
    ? 'The two analyses are identical: every fact, location and limitation matches.'
    : `${added.length} fact(s) added, ${removed.length} removed, ${changed.length} changed; ` +
      `${locationsAdded.length} location(s) added, ${locationsRemoved.length} removed; ` +
      `${limitationsAdded.length} new gap(s), ${limitationsRemoved.length} closed.`;

  return {
    leftId: left.id,
    rightId: right.id,
    identical,
    facts: { added, removed, changed },
    locations: { added: locationsAdded, removed: locationsRemoved },
    limitations: { added: limitationsAdded, removed: limitationsRemoved },
    summary,
  };
}

/** Turn a diff into an Evidence record, so it can be handed to an agent. */
export function diffEvidenceRecord(diff: EvidenceDiff, subject: string): Evidence {
  const facts: Fact[] = [];
  const push = (label: string, value: string | number | boolean) => facts.push({ label, value: String(value) });

  push('diff.identical', diff.identical);
  push('diff.facts_added', diff.facts.added.length);
  push('diff.facts_removed', diff.facts.removed.length);
  push('diff.facts_changed', diff.facts.changed.length);
  push('diff.locations_added', diff.locations.added.length);
  push('diff.locations_removed', diff.locations.removed.length);
  push('diff.limitations_added', diff.limitations.added.length);
  push('diff.limitations_removed', diff.limitations.removed.length);
  for (const change of diff.facts.changed) {
    push(`diff.changed.${change.label}`, `${change.before} → ${change.after}`);
  }

  return makeEvidence({
    kind: 'evidence-diff',
    subject,
    summary: diff.summary,
    facts,
    locations: diff.locations.added.slice(0, 100),
    metrics: [
      { label: 'diff.changed', value: diff.facts.changed.length },
      { label: 'diff.added', value: diff.facts.added.length },
      { label: 'diff.removed', value: diff.facts.removed.length },
    ],
    limitations: [
      'A diff compares what two runs observed; it cannot tell you which run is correct.',
    ],
    data: diff as unknown as Record<string, unknown>,
  });
}
