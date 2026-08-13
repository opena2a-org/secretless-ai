import { describe, it, expect } from 'vitest';
import { leaksAny, redactValues, scrubOrDrop, redactMatches } from './redact';
import { CREDENTIAL_PATTERNS } from './patterns';
import { maskLine } from './scan';

/**
 * The residue oracle.
 *
 * Deliberately NOT string equality against an expected output. An assertion
 * copied from the tool's own output encodes whatever the tool currently does,
 * including the defect — the whole point of #133 is that the output LOOKED
 * redacted (`[GitHub Token REDACTED]iJ4k`) while carrying the credential. So
 * these tests ask the independent question `leaksAny` was written to answer:
 * does any run of the secret's own characters survive anywhere in the text?
 *
 * `leaksAny` is the module's existing detector and takes a different form from
 * the replacement code under test, so it cannot fail in the same direction.
 */
function assertNoResidue(output: string, value: string) {
  expect(leaksAny(output, [value])).toBe(false);
}

/**
 * Prefix-anchored patterns whose quantifier is FIXED, with the shortest value
 * each one accepts. These are the patterns where a real credential one
 * character longer than the quantifier left the overshoot in the output.
 *
 * Values are synthetic and generated from a fixed alphabet — never a real
 * credential, and deliberately free of the literal `FAKE`, which the scanner
 * suppresses as a placeholder (that suppression is what made an earlier
 * walkthrough measure the suppressor instead of the redactor).
 */
const BODY = 'aB3xQ9zK7mR2tY5wL8pN4vC6hJ1sD0gF';
function body(n: number): string {
  let s = '';
  while (s.length < n) s += BODY;
  return s.slice(0, n);
}

const FIXED_LENGTH_PATTERNS: Array<{ id: string; make: (extra: number) => string }> = [
  { id: 'github-pat', make: (x) => 'ghp_' + body(36 + x) },
  { id: 'github-oauth', make: (x) => 'gho_' + body(36 + x) },
  { id: 'github-app', make: (x) => 'ghs_' + body(36 + x) },
  { id: 'npm', make: (x) => 'npm_' + body(36 + x) },
  { id: 'google', make: (x) => 'AIza' + body(35 + x) },
  { id: 'aws-access', make: (x) => 'AKIA' + 'ABCDEFGHIJKLMNOP'.slice(0, 16) + 'Q'.repeat(x) },
  { id: 'aws-sts', make: (x) => 'ASIA' + 'ABCDEFGHIJKLMNOP'.slice(0, 16) + 'Q'.repeat(x) },
  { id: 'twilio', make: (x) => 'SK' + '0123456789abcdef0123456789abcdef'.slice(0, 32) + 'a'.repeat(x) },
];

describe('redactMatches — the redactor is not bounded by the detector (#133)', () => {
  /**
   * The matrix #133 asked for: minimum length, one over, and well over. A suite
   * pinned to one length is what hid this — a correctly-shaped value redacts
   * cleanly at every length the pattern was written for.
   */
  for (const { id, make } of FIXED_LENGTH_PATTERNS) {
    const pattern = CREDENTIAL_PATTERNS.find((p) => p.id === id);
    it(`leaves no residue for ${id} at min, +1 and +8`, () => {
      expect(pattern, `pattern ${id} not found — the table is stale`).toBeDefined();
      for (const extra of [0, 1, 8]) {
        const value = make(extra);
        const line = `TOKEN="${value}"`;
        // Guard the guard: if the pattern stopped matching the value entirely
        // the assertion below would pass vacuously.
        expect(
          new RegExp(pattern!.regex.source).test(line),
          `${id} at +${extra} no longer matches its own pattern`,
        ).toBe(true);
        assertNoResidue(redactMatches(line, pattern!.regex, '[X]'), value);
      }
    });
  }

  it('masks the whole credential through maskLine, the shared display path', () => {
    const pattern = CREDENTIAL_PATTERNS.find((p) => p.id === 'github-pat')!;
    const value = 'ghp_' + body(44);
    assertNoResidue(maskLine(`token: ${value}`, pattern), value);
  });

  /**
   * The other direction, which matters because two callers REWRITE THE USER'S
   * FILE. A redactor that extends too far deletes content the user wrote.
   */
  it('does not consume the path segment after a token inside a URL', () => {
    const pattern = CREDENTIAL_PATTERNS.find((p) => p.id === 'github-pat')!;
    const value = 'ghp_' + body(36);
    const out = redactMatches(`git clone https://x@example.com/p/${value}/repo.git`, pattern.regex, '[X]');
    assertNoResidue(out, value);
    expect(out).toContain('/repo.git');
    expect(out).toContain('https://x@example.com/p/');
  });

  it('redacts every occurrence on a line, not just the first', () => {
    const pattern = CREDENTIAL_PATTERNS.find((p) => p.id === 'github-pat')!;
    const a = 'ghp_' + body(40);
    const b = 'ghp_' + body(37);
    const out = redactMatches(`${a} and ${b}`, pattern.regex, '[X]');
    assertNoResidue(out, a);
    assertNoResidue(out, b);
  });

  it('keeps the gating variable name for capture-group patterns', () => {
    const pattern = CREDENTIAL_PATTERNS.find((p) => p.id === 'aws-secret');
    if (!pattern) return;
    const value = body(40);
    const line = `aws_secret_access_key = "${value}"`;
    const out = redactMatches(line, pattern.regex, '[X]', { preferCaptureGroup: true });
    assertNoResidue(out, value);
    // The name is the useful half of the finding; erasing it rendered the line
    // as a bare quote.
    expect(out).toContain('aws_secret_access_key');
  });

  it('leaves text with no credential untouched', () => {
    const pattern = CREDENTIAL_PATTERNS.find((p) => p.id === 'github-pat')!;
    const line = 'nothing to see here';
    expect(redactMatches(line, pattern.regex, '[X]')).toBe(line);
  });
});

describe('redact — existing primitives still hold', () => {
  it('leaksAny detects a truncated value by run', () => {
    const v = 'sk-live-' + body(40);
    expect(leaksAny(`Received '${v.slice(0, 20)}...'`, [v])).toBe(true);
  });

  it('redactValues replaces longest-first', () => {
    expect(redactValues('abcdef abc', ['abc', 'abcdef'])).toBe('[REDACTED] [REDACTED]');
  });

  it('scrubOrDrop returns empty when residue survives', () => {
    const v = body(40);
    expect(scrubOrDrop(`prefix ${v.slice(0, 10)} suffix`, [v])).toBe('');
  });
});
