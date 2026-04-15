import { describe, it, expect } from 'vitest';
import { isKnownExample, findRealMatch } from './scan';
import { CREDENTIAL_PATTERNS } from './patterns';

function patternByName(name: string) {
  const p = CREDENTIAL_PATTERNS.find(p => p.name === name);
  if (!p) throw new Error(`pattern ${name} not found`);
  return p;
}

describe('isKnownExample (issue #50 — comment-marker precedence)', () => {
  it('does NOT treat a line with # but no "example" as a known example', () => {
    // Python comment line with a credential-shaped value but no "example" marker.
    // Previous buggy precedence `(A && B) || C` would enter the inner block on any
    // line containing `#`. Regression guard: must return false here.
    const line = '# TODO: rotate AKIAREALKEY1234567890 next sprint';
    const match = line.match(/AKIA[0-9A-Z]{16}/)!;
    expect(match).not.toBeNull();
    expect(isKnownExample(line, match)).toBe(false);
  });

  it('DOES treat a line with "example //" as a known example', () => {
    const line = 'const key = "AKIASOMEOTHERKEY12345"; // example placeholder';
    const match = line.match(/AKIA[0-9A-Z]{16}/)!;
    expect(match).not.toBeNull();
    expect(isKnownExample(line, match)).toBe(true);
  });

  it('treats the AKIAIOSFODNN7EXAMPLE public example as a known example', () => {
    const line = 'See AKIAIOSFODNN7EXAMPLE in the AWS docs.';
    const match = line.match(/AKIA[0-9A-Z]{16}/)!;
    expect(isKnownExample(line, match)).toBe(true);
  });
});

describe('findRealMatch (issue #51 — known-example shadowing)', () => {
  it('mixed-pattern line: AWS example + real GitHub PAT returns the PAT', () => {
    // Intentionally NO `//` or `#` markers — we're testing that the KNOWN_EXAMPLE_KEYS
    // match for AKIAIOSFODNN7EXAMPLE does not shadow the real GitHub PAT later on
    // the same line. (Lines with comment+example context are an orthogonal case
    // handled by isKnownExample directly.)
    const line = 'const old = "AKIAIOSFODNN7EXAMPLE"; const new_ = "ghp_abcdefghijklmnopqrstuvwxyz1234567890";';
    const awsPattern = patternByName('AWS Access Key');
    const ghPattern = patternByName('GitHub Token');

    // AWS pattern: only match is the public example -> no real match
    expect(findRealMatch(line, awsPattern)).toBeNull();
    // GitHub pattern: match is real
    const ghMatch = findRealMatch(line, ghPattern);
    expect(ghMatch).not.toBeNull();
    expect(ghMatch![0]).toBe('ghp_abcdefghijklmnopqrstuvwxyz1234567890');
  });

  it('multi-match same-pattern line: example AKIAIOSFODNN7EXAMPLE before real AKIA key returns the real one', () => {
    // AWS Access Key pattern ships without /g; findRealMatch must still iterate
    // every match on the line and skip the example to find the real key.
    const line = 'const keys = ["AKIAIOSFODNN7EXAMPLE", "AKIAREALKEY1234567890"];';
    const awsPattern = patternByName('AWS Access Key');
    const match = findRealMatch(line, awsPattern);
    expect(match).not.toBeNull();
    // AWS regex is AKIA[0-9A-Z]{16} — match is exactly 20 chars, trailing digits truncated.
    expect(match![0]).toBe('AKIAREALKEY123456789');
  });

  it('returns null when every match on the line is a known example', () => {
    const line = '// examples: AKIAIOSFODNN7EXAMPLE';
    const awsPattern = patternByName('AWS Access Key');
    expect(findRealMatch(line, awsPattern)).toBeNull();
  });
});
