/**
 * Per-finding confidence score — deterministic composite for prioritising
 * scan output. Same input produces the same score; no ML, no random seed.
 *
 * Inputs (all clamped to [0, 1] then weighted):
 * - Pattern specificity. Long literal prefixes (`sk-ant-api03-`,
 *   `github_pat_`, `mongodb+srv://`) are strong signals; short prefixes
 *   (`SK`, `eyJ`) overlap with non-credential strings and score lower.
 * - Value entropy. Shannon entropy over the matched value, normalised by
 *   length-aware ceiling. Padded / repeated values (`aaaa…`, `1234…`)
 *   score low even when the regex matched.
 * - Value length tier. Longer matches lift confidence. Tiered, not linear,
 *   so a 64-char OAuth token doesn't dominate a 36-char GitHub PAT.
 * - Path tier. Live source / config files outrank docs (markdown / VHS
 *   tutorials / .golden fixtures). Test fixture paths score lower again.
 *
 * The four sub-scores are combined with fixed weights chosen to preserve
 * monotonicity: a finding that's stronger on every axis MUST score higher.
 *
 * Tier mapping for display:
 *   >= 0.85 → 'high'
 *   0.6  – 0.85 → 'medium'
 *   < 0.6 → 'low'
 *
 * The `--min-confidence <n>` flag (Item 1.b — to be wired in commands/core.ts)
 * filters findings whose composite score is below the threshold.
 */

import type { CredentialPattern } from './patterns';

/** Confidence tier label rendered in CLI output. */
export type ConfidenceTier = 'high' | 'medium' | 'low';

export interface ConfidenceBreakdown {
  /** Composite [0, 1]. */
  score: number;
  /** Display tier. */
  tier: ConfidenceTier;
  /** Sub-scores (debug / explain output). */
  patternScore: number;
  entropyScore: number;
  lengthScore: number;
  pathScore: number;
}

export interface ScoreFindingInput {
  pattern: Pick<CredentialPattern, 'id' | 'regex'>;
  /** The matched value (`match[0]` from the credential regex). */
  value: string;
  /** Repo-relative POSIX path of the file the match was found in. */
  filePath: string;
}

const WEIGHT_PATTERN = 0.35;
const WEIGHT_ENTROPY = 0.30;
const WEIGHT_LENGTH = 0.15;
const WEIGHT_PATH = 0.20;
const TIER_HIGH_THRESHOLD = 0.85;
const TIER_MEDIUM_THRESHOLD = 0.60;

/**
 * Pattern specificity heuristic — measures how much of the regex source is
 * literal characters (the prefix) vs. character classes / quantifiers.
 *
 * Rationale: a regex like `/sk-ant-api\d{2}-[a-zA-Z0-9_-]{20,}/` contains
 * 12 literal chars before the first metaclass — strong prefix anchoring.
 * A regex like `/sk-[a-zA-Z0-9]{48,}/` only has 3 literal chars before the
 * class, so it's intrinsically more collision-prone.
 *
 * Returned in [0, 1]. 12+ literal prefix chars → 1.0; 0 literal prefix → 0.0.
 */
export function patternSpecificity(regex: RegExp): number {
  const src = regex.source;
  let literalChars = 0;
  let i = 0;
  while (i < src.length) {
    const ch = src[i];
    // Stop at the first metacharacter or escape that introduces a class /
    // alternation / quantifier. Backslash followed by `\d`/`\w`/`\s`/`\b`/etc
    // counts as a metaclass, NOT a literal — a literal hyphen or dot in the
    // pattern would be `\-` or `\.` and we DO count those (handled below).
    if (ch === '\\' && i + 1 < src.length) {
      const next = src[i + 1];
      // Literal escapes — count as literal.
      if (/[.+*?^$()|/\\\-]/.test(next)) {
        literalChars += 1;
        i += 2;
        continue;
      }
      // Metaclass escapes — `\d`, `\w`, `\s`, `\b`, etc — stop accumulating.
      break;
    }
    // Non-escape metacharacters end the literal prefix.
    if (/[.+*?^$()|[\]{}]/.test(ch)) break;
    literalChars += 1;
    i += 1;
  }
  // 12+ literal chars saturates. Below that, linear scaling.
  return Math.min(literalChars / 12, 1);
}

/**
 * Shannon entropy of `value`, normalised against a length-aware ceiling.
 *
 * Returns [0, 1]. A 32-char value with 32 distinct chars (max entropy ~5.0
 * bits/symbol) returns 1.0; a 32-char value of repeated chars returns 0.0.
 *
 * Implementation note: `value.length === 0` returns 0 (no signal). For very
 * short values (< 8 chars) we floor at 0 to avoid noise from short tokens.
 */
export function valueEntropy(value: string): number {
  if (value.length < 8) return 0;
  const freq = new Map<string, number>();
  for (const ch of value) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }
  let h = 0;
  for (const count of freq.values()) {
    const p = count / value.length;
    h -= p * Math.log2(p);
  }
  // Theoretical max for an alphabet of size N is log2(N). For credential
  // tokens (mixed case + digits + a few symbols), the practical alphabet
  // is ~64 → max entropy ≈ 6 bits/symbol. We normalise against 5 (which a
  // typical 36-char base62 token comfortably reaches).
  return Math.min(h / 5, 1);
}

/**
 * Tiered length score. Step function so a 200-char value doesn't crowd
 * out a real 36-char GitHub PAT.
 */
export function lengthTier(value: string): number {
  const n = value.length;
  if (n >= 64) return 1.0;
  if (n >= 40) return 0.85;
  if (n >= 28) return 0.7;
  if (n >= 20) return 0.55;
  if (n >= 12) return 0.35;
  return 0.15;
}

/**
 * Path tier — penalises matches in fixture / docs paths and rewards
 * matches in live source / config files.
 *
 * Note: `--no-ignore` callers will see fixture paths in the finding list;
 * the path tier still scores those low so the display ordering doesn't
 * surface them above real source-code findings.
 */
export function pathTier(filePath: string): number {
  // Normalise. Caller usually passes a POSIX-relative path already.
  const p = filePath.replace(/\\/g, '/').toLowerCase();

  // Fixture / test / golden / vhs / examples / e2e paths — clearly demo.
  if (
    p.startsWith('test/') || p.startsWith('tests/') || p.includes('/test/') ||
    p.includes('/tests/') || p.startsWith('__tests__/') || p.includes('/__tests__/') ||
    p.startsWith('__fixtures__/') || p.includes('/__fixtures__/') ||
    p.startsWith('test-server/') || p.includes('/test-server/') ||
    p.startsWith('docs/vhs/') || p.includes('/docs/vhs/') ||
    p.startsWith('examples/') || p.includes('/examples/') ||
    p.startsWith('e2e/') || p.includes('/e2e/') ||
    p.startsWith('.golden/') || p.includes('/.golden/') ||
    /\.(test|spec|e2e)\.[a-z0-9]+$/i.test(p)
  ) {
    return 0.2;
  }
  // Documentation paths — credentials in docs are usually example.
  if (p.endsWith('.md') || p.endsWith('.mdx') || p.endsWith('.rst')) {
    return 0.4;
  }
  // Config files — high confidence (this is where real creds live).
  if (
    p.endsWith('.env') || /\.env\.[^/]+$/.test(p) ||
    p === '.envrc' || p.endsWith('/.envrc') ||
    p.endsWith('settings.json') || p.endsWith('.claude/settings.json') ||
    p.endsWith('config.json') || p.endsWith('config.yaml') || p.endsWith('config.yml')
  ) {
    return 1.0;
  }
  // Source code default — moderate-high.
  return 0.85;
}

/**
 * Compose the four sub-scores into a single confidence value.
 * Pure function — same input → same output.
 */
export function scoreFinding(input: ScoreFindingInput): ConfidenceBreakdown {
  const patternScore = patternSpecificity(input.pattern.regex);
  const entropyScore = valueEntropy(input.value);
  const lengthScore = lengthTier(input.value);
  const pathScore = pathTier(input.filePath);

  const score =
    WEIGHT_PATTERN * patternScore +
    WEIGHT_ENTROPY * entropyScore +
    WEIGHT_LENGTH * lengthScore +
    WEIGHT_PATH * pathScore;

  // Clamp defensively. The weights sum to 1.0 and each sub-score is in
  // [0, 1], so the composite is already in [0, 1] — but FP arithmetic.
  const clamped = Math.max(0, Math.min(1, score));
  const tier: ConfidenceTier =
    clamped >= TIER_HIGH_THRESHOLD ? 'high' :
    clamped >= TIER_MEDIUM_THRESHOLD ? 'medium' :
    'low';

  return {
    score: Math.round(clamped * 1000) / 1000,
    tier,
    patternScore: Math.round(patternScore * 1000) / 1000,
    entropyScore: Math.round(entropyScore * 1000) / 1000,
    lengthScore: Math.round(lengthScore * 1000) / 1000,
    pathScore: Math.round(pathScore * 1000) / 1000,
  };
}

/**
 * Render helper for CLI output. Deterministic: returns the tier label
 * and a parenthesised numeric score.
 */
export function formatConfidence(breakdown: ConfidenceBreakdown): string {
  return `${breakdown.tier} (${breakdown.score.toFixed(2)})`;
}
