/**
 * Masking every credential on a line.
 *
 * Every preview the tool prints of a line is built here (`scan` text and
 * `--json`, `scan-history`, `diff`), and so is the line `clean-history` writes
 * back. Each credential on the line, not only the one a finding reports, is
 * replaced through the end of its trailing credential characters by one marker,
 * and no character of any value is kept. The marker is `[<pattern name>
 * REDACTED]`, the one `scan` prints, unless the caller passes its own.
 *
 * The spans of every pattern are found on the line as written and merged where
 * they overlap, and only then replaced, so a credential is replaced whole
 * whichever patterns match parts of it. A merged span carries the marker of the
 * credential that starts first.
 */

import { CREDENTIAL_PATTERNS, type CredentialPattern } from './patterns';
import { credentialSpans } from './redact';

/** What masking reads of a pattern. */
export type MaskPattern = Pick<CredentialPattern, 'id' | 'name' | 'regex'>;

export interface MaskOptions {
  /**
   * Patterns that find a value by the command around it rather than by its
   * format: shell history's `export NAME=`, `--api-key`, `Authorization:
   * Bearer` and `secret set NAME=`. Where that value is a credential of a known
   * format, such a pattern matches it a second time together with the command.
   * Each is therefore applied where it still matches once every credential
   * `CREDENTIAL_PATTERNS` found on the line is cut down to one character: then
   * it has found a value no format accounts for, and its spans on the line as
   * written are merged in. A command whose value is a known-format credential
   * keeps its words, and the credential its own marker.
   */
  commandPatterns?: readonly MaskPattern[];
  /** What replaces a span. Default `[<pattern name> REDACTED]`. */
  label?: (pattern: MaskPattern) => string;
  /**
   * Default true. A pattern that captures its value in group 1 (the name-gated
   * `aws-secret`, or `secret set NAME=VALUE`) keeps the text before the value,
   * so a preview still shows which variable is exposed. `clean-history` passes
   * false and replaces the whole match, as its rewrite always has.
   */
  preferCaptureGroup?: boolean;
}

interface Span {
  from: number;
  to: number;
  /** The pattern's position: the earlier pattern labels a span two patterns start together. */
  rank: number;
  pattern: MaskPattern;
}

/** What a known-format credential is cut down to while the command patterns are tried. */
const CUT_DOWN = '\u0000';

/**
 * `line` with every credential on it replaced by its marker.
 *
 * Masks every `CREDENTIAL_PATTERNS` entry, plus `options.commandPatterns`,
 * across the whole line. Text no pattern matches comes back unchanged.
 */
export function maskCredentials(line: string, options: MaskOptions = {}): string {
  const preferCaptureGroup = options.preferCaptureGroup ?? true;
  const spans: Span[] = [];
  const add = (pattern: MaskPattern, rank: number) => addSpans(spans, line, pattern, rank, preferCaptureGroup);

  CREDENTIAL_PATTERNS.forEach(add);
  const commands = options.commandPatterns ?? [];
  if (commands.length > 0) {
    const rest = render(line, merged(spans), () => CUT_DOWN);
    commands.forEach((pattern, i) => {
      if (rest.search(pattern.regex) !== -1) add(pattern, CREDENTIAL_PATTERNS.length + i);
    });
  }

  const label = options.label ?? ((pattern: MaskPattern) => `[${pattern.name} REDACTED]`);
  return render(line, merged(spans), label);
}

/** A marker `maskCredentials(line)` writes: the pattern it names and the part of the line it replaces. */
export interface Marker {
  pattern: MaskPattern;
  from: number;
  to: number;
}

/**
 * The marker `maskCredentials(line)`, called with no options, writes over the
 * character at `at`, or undefined where that preview keeps the character.
 */
export function markerAt(line: string, at: number): Marker | undefined {
  const spans: Span[] = [];
  CREDENTIAL_PATTERNS.forEach((pattern, rank) => addSpans(spans, line, pattern, rank, true));
  const span = merged(spans).find((s) => s.from <= at && at < s.to);
  return span && { pattern: span.pattern, from: span.from, to: span.to };
}

function addSpans(spans: Span[], line: string, pattern: MaskPattern, rank: number, preferCaptureGroup: boolean): void {
  for (const { from, to } of credentialSpans(line, pattern.regex, { preferCaptureGroup })) {
    spans.push({ from, to, rank, pattern });
  }
}

/** The spans in line order, overlapping ones joined and labelled by the one that starts first. */
function merged(spans: readonly Span[]): Span[] {
  const sorted = [...spans].sort((a, b) => a.from - b.from || a.rank - b.rank);
  const out: Span[] = [];
  for (const span of sorted) {
    const last = out[out.length - 1];
    if (last && span.from < last.to) last.to = Math.max(last.to, span.to);
    else out.push({ ...span });
  }
  return out;
}

function render(line: string, spans: readonly Span[], label: (pattern: MaskPattern) => string): string {
  let out = '';
  let cursor = 0;
  for (const span of spans) {
    out += line.slice(cursor, span.from) + label(span.pattern);
    cursor = span.to;
  }
  return out + line.slice(cursor);
}
