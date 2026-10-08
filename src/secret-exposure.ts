/**
 * Exposed secrets that still need rotating (#236).
 *
 * A key pasted into a chat, shown on screen or committed is still live after a
 * transcript is redacted: only a new value at the provider ends the exposure.
 * The record of it lives in the secret's existing metadata, beside the store and
 * never with the value:
 *
 *   exposedAt     when the value was exposed (ISO 8601)
 *   exposedWhere  a short note saying where
 *   rotatedAt     when a different value last closed an exposure
 *
 * An exposure is open while `exposedAt` is recorded. `secret set` with a value
 * that differs from the stored one closes it; the same value leaves it open. The
 * store compares the two in memory, so no hash or other derivative of a value is
 * kept anywhere.
 */

import type { AnnotationMap, AnnotationUpdate, SecretAnnotation } from './secret-annotations';
import type { SecretStore } from './secret-store';

export const EXPOSED_AT = 'exposedAt';
export const EXPOSED_WHERE = 'exposedWhere';
export const ROTATED_AT = 'rotatedAt';

/**
 * A stored value shorter than this counts as exposed only when a redacted span
 * equals it. Longer, it counts when a span contains it: a name-gated pattern
 * (`AWS_SECRET_ACCESS_KEY = "..."`) redacts the variable name with the value.
 * The same floor `checkAnnotation` uses for containment.
 */
const MIN_CONTAINED_VALUE = 8;

/** Longest `exposedWhere` this module writes; the metadata value limit. */
const MAX_WHERE_LENGTH = 1024;

export interface OpenExposure {
  exposedAt: string;
  exposedWhere: string | null;
}

/** One open exposure as `secret list --needs-rotation` reports it. */
export interface NeedsRotation extends OpenExposure {
  name: string;
  provider: string | null;
}

/** The open exposure recorded for a secret, or null when there is none. */
export function openExposure(annotation: SecretAnnotation | undefined): OpenExposure | null {
  const exposedAt = annotation?.meta[EXPOSED_AT];
  if (!exposedAt) return null;
  return { exposedAt, exposedWhere: annotation!.meta[EXPOSED_WHERE] || null };
}

/** Every open exposure, in name order. Reads metadata only, never a value. */
export function needsRotation(annotations: AnnotationMap): NeedsRotation[] {
  const out: NeedsRotation[] = [];
  for (const name of [...annotations.keys()].sort()) {
    const annotation = annotations.get(name);
    const exposure = openExposure(annotation);
    if (!exposure) continue;
    out.push({ name, ...exposure, provider: annotation!.meta.provider || null });
  }
  return out;
}

/** The metadata change that records an exposure. */
export function exposureUpdate(at: Date, where: string): AnnotationUpdate {
  return { meta: { [EXPOSED_AT]: at.toISOString(), [EXPOSED_WHERE]: where } };
}

/**
 * The metadata change that closes an exposure, merged under the caller's own
 * update: a key the caller sets explicitly keeps the caller's value.
 */
export function rotationUpdate(at: Date, update: AnnotationUpdate | undefined): AnnotationUpdate {
  const meta: Record<string, string> = { [EXPOSED_AT]: '', [EXPOSED_WHERE]: '', [ROTATED_AT]: at.toISOString() };
  for (const [key, value] of Object.entries(update?.meta ?? {})) {
    Object.defineProperty(meta, key, { value, enumerable: true, writable: true, configurable: true });
  }
  const merged: AnnotationUpdate = { meta };
  if (update?.description !== undefined) merged.description = update.description;
  return merged;
}

/**
 * Read `--at`: a date (`2026-10-07`) or a date and time in ISO 8601. Returns the
 * time, or the reason it cannot be used. A time in the future is refused: an
 * exposure is something that already happened.
 */
export function parseExposureTime(input: string, now: Date = new Date()): Date | string {
  if (!/^\d{4}-\d{2}-\d{2}([T ][0-9:.]+(Z|[+-]\d{2}:?\d{2})?)?$/.test(input)) {
    return `--at takes a date such as 2026-10-07 or a time such as 2026-10-07T14:30:00Z, not "${input.slice(0, 40)}".`;
  }
  // Checked on the calendar date itself: some runtimes roll 2026-02-30 over to
  // March rather than refusing it.
  const [y, m, d] = input.slice(0, 10).split('-').map(Number);
  const day = new Date(Date.UTC(y, m - 1, d));
  const at = new Date(input);
  if (day.getUTCMonth() !== m - 1 || day.getUTCDate() !== d || Number.isNaN(at.getTime())) {
    return `--at "${input}" is not a date that exists.`;
  }
  if (at.getTime() > now.getTime()) return `--at ${input} is in the future; give the time the value was exposed.`;
  return at;
}

/** One span `clean` or `watch` redacted, and where. The span is credential text. */
export interface RedactedSpan {
  span: string;
  file: string;
  line: number;
}

/**
 * Stored secrets whose value was in a redacted span, each with the first place
 * it was found. Compared in memory; neither the spans nor the values leave it.
 */
export function storedSecretsIn(
  spans: readonly RedactedSpan[],
  stored: Readonly<Record<string, string>>,
): Array<{ name: string; file: string; line: number }> {
  const out: Array<{ name: string; file: string; line: number }> = [];
  for (const name of Object.keys(stored).sort()) {
    const value = stored[name];
    if (!value) continue;
    const hit = spans.find((s) => s.span === value || (value.length >= MIN_CONTAINED_VALUE && s.span.includes(value)));
    if (hit) out.push({ name, file: hit.file, line: hit.line });
  }
  return out;
}

/** `exposedWhere` for a transcript location: one printable line within the limit. */
export function transcriptWhere(file: string, line: number, foundBy: 'clean' | 'watch'): string {
  const suffix = ` line ${line} (found by ${foundBy})`;
  const room = MAX_WHERE_LENGTH - 'transcript '.length - suffix.length;
  let shown = file.replace(/[\u0000-\u001f\u007f-\u009f]/g, '?');
  if (shown.length > room) shown = '...' + shown.slice(shown.length - room + 3);
  return `transcript ${shown}${suffix}`;
}

export interface ExposureMarks {
  /** Newly marked exposed, or on a dry run, would be. */
  marked: Array<{ name: string; where: string }>;
  /** Already open before this run; left as recorded. */
  alreadyOpen: Array<{ name: string; exposedAt: string }>;
  /** Matched, but the record could not be written. */
  failed: Array<{ name: string; reason: string }>;
  /** Set when the stored values could not be read, so nothing was compared. */
  notChecked?: string;
}

/**
 * Mark exposed every stored secret whose value `clean` or `watch` redacted.
 *
 * The store is read only when something was redacted, so a clean run never
 * unlocks it. An exposure that is already open keeps its first record. A store
 * that cannot be read is reported, not thrown: the redaction already happened
 * and is the job that matters.
 */
export async function markRedactedSecretsExposed(
  spans: readonly RedactedSpan[],
  createStore: () => SecretStore,
  options: { foundBy: 'clean' | 'watch'; dryRun?: boolean; now?: Date },
): Promise<ExposureMarks> {
  const marks: ExposureMarks = { marked: [], alreadyOpen: [], failed: [] };
  if (spans.length === 0) return marks;

  let store: SecretStore;
  let matches: Array<{ name: string; file: string; line: number }>;
  let annotations: AnnotationMap;
  try {
    store = createStore();
    matches = storedSecretsIn(spans, await store.loadSecrets());
    annotations = matches.length > 0 ? store.listAnnotations() : new Map();
  } catch (err) {
    marks.notChecked = firstLine(err);
    return marks;
  }

  const now = options.now ?? new Date();
  for (const match of matches) {
    const open = openExposure(annotations.get(match.name));
    if (open) {
      marks.alreadyOpen.push({ name: match.name, exposedAt: open.exposedAt });
      continue;
    }
    const where = transcriptWhere(match.file, match.line, options.foundBy);
    if (options.dryRun) {
      marks.marked.push({ name: match.name, where });
      continue;
    }
    try {
      await store.recordExposure(match.name, where, now);
      marks.marked.push({ name: match.name, where });
    } catch (err) {
      marks.failed.push({ name: match.name, reason: firstLine(err) });
    }
  }
  return marks;
}

function firstLine(err: unknown): string {
  const message = err instanceof Error ? err.message : String(err);
  return message.split('\n').find((l) => l.trim() !== '')?.trim() ?? 'unknown error';
}
