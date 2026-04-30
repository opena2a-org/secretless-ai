/**
 * Tests for src/confidence.ts — per-finding confidence score.
 *
 * Determinism: every test calls `scoreFinding` (or its sub-scorers) with
 * static inputs and asserts a fixed numeric result. No fixtures with real
 * credential values: token shapes are constructed via [].join('') so
 * GitHub Push Protection doesn't flag them (precedent: src/patterns.test.ts:12).
 */

import { describe, it, expect } from 'vitest';
import {
  patternSpecificity,
  valueEntropy,
  lengthTier,
  pathTier,
  scoreFinding,
  formatConfidence,
} from './confidence';

// Synthesise token shapes by joining literal segments — these aren't real
// credentials and won't trip secret scanners.
const ANT_PREFIX = ['sk', '-ant', '-api03', '-'].join('');
const GH_PREFIX = ['ghp', '_'].join('');
const SK_PREFIX = ['sk', '-'].join('');

describe('patternSpecificity', () => {
  it('saturates at 1.0 for 12+ literal prefix characters', () => {
    // "sk-ant-api\d{2}-..." has 10 literal chars before the metaclass.
    const r1 = /sk-ant-api\d{2}-[a-zA-Z0-9_-]{20,}/;
    expect(patternSpecificity(r1)).toBeCloseTo(10 / 12, 5);
  });

  it('scores 0.25 for a 3-char prefix (sk-) before the class', () => {
    const r = /sk-[a-zA-Z0-9]{48,}/;
    expect(patternSpecificity(r)).toBeCloseTo(3 / 12, 5);
  });

  it('counts literal escape `\\.` as a literal char', () => {
    // `mongodb\+srv:\/\/...` — `\\+` is a literal `+`, `\\/` is a literal `/`.
    const r = /mongodb\+srv:\/\/[^\s]{10,}/;
    // Literal prefix: `m`, `o`, `n`, `g`, `o`, `d`, `b`, `+` (escaped), `s`,
    // `r`, `v`, `:`, `/` (escaped), `/` (escaped) = 14 → saturates to 1.0.
    expect(patternSpecificity(r)).toBe(1.0);
  });

  it('returns 0 for a regex that opens with a metaclass', () => {
    const r = /[a-zA-Z]{40,}/;
    expect(patternSpecificity(r)).toBe(0);
  });

  it('treats `\\d`, `\\w`, `\\s` as metaclasses (stops counting)', () => {
    const r = /AKIA\d{16}/;
    // 4 literals before `\d`.
    expect(patternSpecificity(r)).toBeCloseTo(4 / 12, 5);
  });
});

describe('valueEntropy', () => {
  it('returns 0 for values shorter than 8 chars (noise floor)', () => {
    expect(valueEntropy('abc')).toBe(0);
    expect(valueEntropy('1234567')).toBe(0);
  });

  it('returns ~1.0 for high-entropy mixed-case alphanumeric', () => {
    const v = 'aB3kP9xQ2mZvW7nY4tL6rJ8sH1cF5gD0eA';
    const score = valueEntropy(v);
    expect(score).toBeGreaterThanOrEqual(0.9);
    expect(score).toBeLessThanOrEqual(1.0);
  });

  it('returns 0 for repeated single-character padding', () => {
    expect(valueEntropy('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')).toBe(0);
  });

  it('returns lower entropy for two-character alternation than full alphabet', () => {
    const alt = valueEntropy('ababababababababababababababab');
    const full = valueEntropy('aB3kP9xQ2mZvW7nY4tL6rJ8sH1cF5gD0');
    expect(alt).toBeLessThan(full);
  });

  it('is deterministic — identical input produces identical output', () => {
    const v = 'aB3kP9xQ2mZvW7nY4tL6rJ8sH1cF5gD0';
    expect(valueEntropy(v)).toBe(valueEntropy(v));
  });
});

describe('lengthTier', () => {
  it('returns 1.0 for 64+ chars', () => {
    expect(lengthTier('x'.repeat(64))).toBe(1.0);
    expect(lengthTier('x'.repeat(120))).toBe(1.0);
  });

  it('returns 0.85 for 40-63 chars', () => {
    expect(lengthTier('x'.repeat(40))).toBe(0.85);
    expect(lengthTier('x'.repeat(63))).toBe(0.85);
  });

  it('returns 0.7 for 28-39 chars (typical PAT length range)', () => {
    expect(lengthTier('x'.repeat(36))).toBe(0.7);
  });

  it('returns 0.15 for very short values', () => {
    expect(lengthTier('abc')).toBe(0.15);
  });

  it('is monotone non-decreasing across length tiers', () => {
    const tiers = [11, 12, 19, 20, 27, 28, 39, 40, 63, 64].map(lengthTier);
    for (let i = 1; i < tiers.length; i++) {
      expect(tiers[i]).toBeGreaterThanOrEqual(tiers[i - 1]);
    }
  });
});

describe('pathTier', () => {
  it('penalises fixture / test / VHS / examples paths', () => {
    expect(pathTier('test/fixtures/secrets.txt')).toBe(0.2);
    expect(pathTier('tests/scan.test.ts')).toBe(0.2);
    expect(pathTier('packages/x/__tests__/foo.ts')).toBe(0.2);
    expect(pathTier('docs/vhs/setup-lab.sh')).toBe(0.2);
    expect(pathTier('examples/openai-demo.js')).toBe(0.2);
    expect(pathTier('e2e/api.spec.ts')).toBe(0.2);
    expect(pathTier('.golden/scan-output.txt')).toBe(0.2);
    expect(pathTier('packages/x/.golden/output.txt')).toBe(0.2);
  });

  it('penalises *.test.ts / *.spec.js by file extension', () => {
    expect(pathTier('src/scan.test.ts')).toBe(0.2);
    expect(pathTier('src/api.spec.js')).toBe(0.2);
  });

  it('returns 0.4 for documentation files', () => {
    expect(pathTier('README.md')).toBe(0.4);
    expect(pathTier('docs/api.mdx')).toBe(0.4);
    expect(pathTier('docs/index.rst')).toBe(0.4);
  });

  it('returns 1.0 for env / config files', () => {
    expect(pathTier('.env')).toBe(1.0);
    expect(pathTier('.env.local')).toBe(1.0);
    expect(pathTier('apps/web/.env.production')).toBe(1.0);
    expect(pathTier('.envrc')).toBe(1.0);
    expect(pathTier('.claude/settings.json')).toBe(1.0);
    expect(pathTier('config.yaml')).toBe(1.0);
  });

  it('returns 0.85 for source code by default', () => {
    expect(pathTier('src/index.ts')).toBe(0.85);
    expect(pathTier('apps/api/handler.go')).toBe(0.85);
    expect(pathTier('lib/auth.py')).toBe(0.85);
  });

  it('handles backslash-separated Windows paths via normalisation', () => {
    expect(pathTier('test\\fixtures\\secrets.txt')).toBe(0.2);
  });

  it('handles uppercase mixed-case paths', () => {
    expect(pathTier('TEST/Fixtures/Foo.ts')).toBe(0.2);
  });
});

describe('scoreFinding (composite)', () => {
  const STRONG_VALUE = ANT_PREFIX + 'aB3kP9xQ2mZvW7nY4tL6rJ8sH1cF5gD0eA';
  const STRONG_PATTERN = { id: 'anthropic', regex: /sk-ant-api\d{2}-[a-zA-Z0-9_-]{20,}/ };
  const WEAK_PATTERN = { id: 'short-prefix', regex: /[A-Z]{4}[0-9]{8,}/ };

  it('returns tier "high" for an env-file Anthropic-shape match', () => {
    const r = scoreFinding({
      pattern: STRONG_PATTERN,
      value: STRONG_VALUE,
      filePath: '.env',
    });
    expect(r.tier).toBe('high');
    expect(r.score).toBeGreaterThanOrEqual(0.85);
  });

  it('returns tier "low" for a fixture-path same-shape match', () => {
    const r = scoreFinding({
      pattern: STRONG_PATTERN,
      value: STRONG_VALUE,
      filePath: 'test/fixtures/api-keys.txt',
    });
    // Path tier 0.2 (fixture) drops the composite below 0.85.
    expect(r.tier).not.toBe('high');
    expect(r.score).toBeLessThan(0.85);
  });

  it('returns tier "low" for a weak-pattern + low-entropy match', () => {
    const r = scoreFinding({
      pattern: WEAK_PATTERN,
      value: 'ABCD11111111',
      filePath: 'README.md',
    });
    expect(r.tier).toBe('low');
    expect(r.score).toBeLessThan(0.6);
  });

  it('is deterministic — same input → same composite score', () => {
    const args = {
      pattern: STRONG_PATTERN,
      value: STRONG_VALUE,
      filePath: 'src/api.ts',
    };
    const a = scoreFinding(args);
    const b = scoreFinding(args);
    expect(a.score).toBe(b.score);
    expect(a.tier).toBe(b.tier);
  });

  it('preserves monotonicity: stronger on every axis ⇒ higher score', () => {
    const weak = scoreFinding({
      pattern: WEAK_PATTERN,
      value: 'AAAA11111111',  // low entropy, 12-char minimum
      filePath: 'docs/api.md',
    });
    const stronger = scoreFinding({
      pattern: STRONG_PATTERN,
      value: STRONG_VALUE,
      filePath: '.env',
    });
    expect(stronger.score).toBeGreaterThan(weak.score);
    expect(stronger.patternScore).toBeGreaterThanOrEqual(weak.patternScore);
    expect(stronger.entropyScore).toBeGreaterThanOrEqual(weak.entropyScore);
    expect(stronger.lengthScore).toBeGreaterThanOrEqual(weak.lengthScore);
    expect(stronger.pathScore).toBeGreaterThanOrEqual(weak.pathScore);
  });

  it('clamps composite to [0, 1]', () => {
    const r = scoreFinding({
      pattern: STRONG_PATTERN,
      value: STRONG_VALUE.repeat(2),
      filePath: '.env',
    });
    expect(r.score).toBeLessThanOrEqual(1);
    expect(r.score).toBeGreaterThanOrEqual(0);
  });

  it('exposes the four sub-scores in the breakdown', () => {
    const r = scoreFinding({
      pattern: STRONG_PATTERN,
      value: STRONG_VALUE,
      filePath: '.env',
    });
    expect(typeof r.patternScore).toBe('number');
    expect(typeof r.entropyScore).toBe('number');
    expect(typeof r.lengthScore).toBe('number');
    expect(typeof r.pathScore).toBe('number');
  });

  it('the github-pat shape on a markdown doc still scores below "high"', () => {
    const r = scoreFinding({
      pattern: { id: 'github-pat', regex: /ghp_[a-zA-Z0-9]{36}/ },
      value: GH_PREFIX + 'aB3kP9xQ2mZvW7nY4tL6rJ8sH1cF5gD0eAbZ',
      filePath: 'README.md',
    });
    // Path tier 0.4 alone is enough to keep this off "high" — protects against
    // the "documentation example" FP class.
    expect(r.tier).not.toBe('high');
  });
});

describe('formatConfidence', () => {
  it('renders tier + score with two decimals', () => {
    const out = formatConfidence({
      score: 0.872,
      tier: 'high',
      patternScore: 1, entropyScore: 1, lengthScore: 1, pathScore: 1,
    });
    expect(out).toBe('high (0.87)');
  });

  it('rounds 0.6 to "0.60" for the medium tier display', () => {
    const out = formatConfidence({
      score: 0.6,
      tier: 'medium',
      patternScore: 0.5, entropyScore: 0.5, lengthScore: 0.5, pathScore: 0.5,
    });
    expect(out).toBe('medium (0.60)');
  });
});

// Suppress unused-var lint — kept for any future test that wants the prefix.
void SK_PREFIX;
