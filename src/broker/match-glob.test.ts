/**
 * #141. `matchGlob` compiled a selector to a regex by replacing each `*` with
 * `[\s\S]*`, so a selector with several wildcards became nested quantifiers
 * and a FAILING match backtracked exponentially: `"*a" x 10` against forty
 * `a`s took 15.56 s, and `"*a" x 14` did not return within 120 s. The pattern
 * is the operator's, but the value is the requester's, and `evaluate()` walks
 * every deny rule first, so one such rule let a request stall the deny loop.
 *
 * The matcher must bound its work by the input sizes, and must keep the exact
 * semantics the regex had — including the line-terminator fix documented on
 * the function — or a deny rule changes meaning.
 */
import { describe, it, expect } from 'vitest';
import { matchGlob } from './policy';

/** The previous implementation, kept here as the semantic reference. */
function regexGlob(pattern: string, value: string): boolean {
  if (pattern === '*') return true;
  if (pattern === value) return true;
  const escaped = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '[\\s\\S]*')
    .replace(/\?/g, '[\\s\\S]');
  return new RegExp(`^${escaped}$`).test(value);
}

describe('matchGlob bounds its work on a failing match (#141)', () => {
  it('rejects a many-wildcard selector against a long non-matching value quickly', () => {
    // Failing matches are the costly shape: the trailing `b` never appears, so
    // a backtracking matcher tries every split of the `a`s among the wildcards.
    // These sizes stay bounded on the old regex (measured 1.2 s and ~5 s), so a
    // regression fails this test instead of hanging the suite; one more
    // wildcard roughly quadruples it.
    const cases: Array<[string, string]> = [
      ['*a'.repeat(8) + 'b', 'a'.repeat(40)],
      ['*a'.repeat(9) + 'b', 'a'.repeat(40)],
    ];
    for (const [pattern, value] of cases) {
      const start = process.hrtime.bigint();
      const result = matchGlob(pattern, value);
      const ms = Number(process.hrtime.bigint() - start) / 1e6;
      expect(result).toBe(false);
      expect(ms, `${pattern.length}-char selector vs ${value.length}-char value took ${ms.toFixed(1)} ms`).toBeLessThan(250);
    }
  });

  it('still returns the right answer on the costly shapes', () => {
    expect(matchGlob('*a'.repeat(10), 'a'.repeat(40))).toBe(true);
    expect(matchGlob('*a'.repeat(10) + 'b', 'a'.repeat(40))).toBe(false);
    expect(matchGlob('*a'.repeat(41), 'a'.repeat(40))).toBe(false);
  });
});

describe('matchGlob keeps the regex semantics exactly (#141)', () => {
  // A deterministic generator, so a failure names a reproducible case.
  let seed = 0x5eed1e55;
  const rand = (n: number) => {
    seed = (seed * 1103515245 + 12345) & 0x7fffffff;
    return seed % n;
  };
  const patternAlphabet = ['*', '?', 'a', 'b', '_', '-', '.', '+', '(', ')', '[', ']', '\\', '^', '$', '|', '{', '}', '\n', ' ', 'A'];
  const valueAlphabet = ['a', 'b', '_', '-', '.', '+', '(', ')', '[', ']', '\\', '^', '$', '|', '{', '}', '\n', '\r', ' ', '*', '?', 'A', '\u{1F511}'];
  const pick = (alphabet: string[], max: number) => {
    let s = '';
    const len = rand(max + 1);
    for (let i = 0; i < len; i++) s += alphabet[rand(alphabet.length)];
    return s;
  };

  it('agrees with the previous regex on 20,000 generated selector/value pairs', () => {
    const mismatches: string[] = [];
    for (let i = 0; i < 20000 && mismatches.length < 5; i++) {
      const pattern = pick(patternAlphabet, 6);
      const value = pick(valueAlphabet, 8);
      if (matchGlob(pattern, value) !== regexGlob(pattern, value)) {
        mismatches.push(JSON.stringify({ pattern, value, expected: regexGlob(pattern, value) }));
      }
    }
    expect(mismatches).toEqual([]);
  });

  it('agrees on the documented edge cases', () => {
    const cases: Array<[string, string]> = [
      ['AWS_*', 'AWS_KEY\n'],
      ['AWS_*', 'AWS_KEY '],
      ['*', ''],
      ['', ''],
      ['?', ''],
      ['?', '\u{1F511}'],
      ['??', '\u{1F511}'],
      ['a*b*c', 'abc'],
      ['a*b*c', 'aXbYc'],
      ['a*b*c', 'aXbY'],
      ['*.*', 'name.with.dots'],
      ['(x)+', '(x)+'],
      ['(x)+', 'xx'],
      ['*', 'anything\nat all'],
      ['**', ''],
      ['a**', 'a'],
    ];
    for (const [pattern, value] of cases) {
      expect(matchGlob(pattern, value), JSON.stringify([pattern, value])).toBe(regexGlob(pattern, value));
    }
  });
});
