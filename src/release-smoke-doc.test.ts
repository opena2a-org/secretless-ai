import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

/**
 * `docs/testing/release-smoke.md` is followed by hand before every tag push.
 * Section 0 gave `npm test` a baseline of 1206 tests, which #213 reported out
 * of date. A count of tests on the page goes out of date when the next test is
 * added, so the step asks for an all-green run and the page names no count.
 */

const SMOKE = path.resolve(__dirname, '..', 'docs', 'testing', 'release-smoke.md');

/** Each count of tests `line` states: "1206 tests", "2,396 passing tests", "Tests  2396 passed". */
function testCounts(line: string): string[] {
  return line.match(/\b\d[\d,]*\s+(?:(?:passing|unit)\s+)?tests?\b|\bTests?(?:\s+Files)?\s+\d[\d,]*\s+passed\b/gi) ?? [];
}

describe('the release smoke names no count of tests (#213)', () => {
  it('reads a count of tests in a line, and no other number', () => {
    expect(testCounts('npm test                   # all green (baseline: 1206 tests)')).toEqual(['1206 tests']);
    expect(testCounts('the 2,396 passing tests and 1 unit test')).toEqual(['2,396 passing tests', '1 unit test']);
    expect(testCounts('      Tests  2398 passed (2398)')).toEqual(['Tests  2398 passed']);
    expect(testCounts(' Test Files  110 passed (110)')).toEqual(['Test Files  110 passed']);
    expect(testCounts('npm test                   # all green')).toEqual([]);
    expect(testCounts('$SL init .          # Created: hooks + settings.json (147 deny patterns)')).toEqual([]);
  });

  it('section 0 runs npm test and passes it when the run is all green', () => {
    const page = fs.readFileSync(SMOKE, 'utf-8');
    const start = page.indexOf('\n## 0. ');
    expect(start, 'release-smoke.md must hold a "## 0." section').toBeGreaterThan(-1);
    const end = page.indexOf('\n## ', start + 1);
    const step = page.slice(start, end === -1 ? undefined : end).split('\n').find((line) => /^npm test\b/.test(line));
    expect(step, 'the npm test step of section 0').toBeDefined();
    expect(step).toMatch(/#\s*all green\b/);
  });

  it('names no count of tests on any line', () => {
    const found = fs.readFileSync(SMOKE, 'utf-8').split('\n')
      .flatMap((line, i) => testCounts(line).map((count) => `docs/testing/release-smoke.md:${i + 1}: ${count}`));
    expect(found, 'a count of tests on the page is out of date when the next test is added').toEqual([]);
  });
});
