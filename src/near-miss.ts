/**
 * Near-miss suggestion — "did you mean X?" for a token the user typed that we
 * do not recognise.
 *
 * A leaf module with no imports, because both callers need it and neither
 * should have to depend on the other: `secret-store` suggests a stored secret
 * name for an unmatched `--only` entry, and `argv` suggests a real flag for a
 * misspelled one. A second copy of an edit distance is how two callers drift
 * to two different definitions of "close enough".
 */

/**
 * How far apart two names may be and still be offered as a suggestion.
 * At 2, `--dryrun` reaches `--dry-run` (one insertion) and `AWS_KEY` reaches
 * `AWS_KEYS`, while unrelated names stay unsuggested.
 */
export const NEAR_MISS_MAX = 2;

/** Anything above the threshold; all such values are equivalent to the caller. */
export const OVER = NEAR_MISS_MAX + 1;

/**
 * Table cells evaluated since the last reset, summed across every call.
 *
 * The band and the row cutoff below are pure optimisations: they change what
 * gets computed, never what gets returned. Cost is therefore their ONLY
 * observable, and reading that cost off a clock measures the machine at least
 * as much as the code — the assertion this replaced went red on source it could
 * not have been affected by, while staying green on a build with the band taken
 * out entirely. This counts the work instead. The count is an exact integer,
 * identical on every machine.
 *
 * @internal Observation only. Nothing outside `*.test.ts` may read it, and no
 * behaviour depends on its value — a work counter that feeds back into control
 * flow is a degradation path whose trigger a caller sets by growing the store.
 * Not exported from `src/index.ts`; present in the published types only because
 * the package ships `dist/`.
 */
let cellsEvaluated = 0;

/** @internal Test observation only — see {@link cellsEvaluated}. */
export function nearMissCellsEvaluated(): number {
  return cellsEvaluated;
}

/** @internal Test observation only — see {@link cellsEvaluated}. */
export function resetNearMissCellsEvaluated(): void {
  cellsEvaluated = 0;
}

/**
 * Case-insensitive edit distance, only ever used to suggest a typo fix.
 * Any result above NEAR_MISS_MAX is returned as OVER, not computed exactly.
 *
 * BANDED. Only cells within NEAR_MISS_MAX of the diagonal are evaluated, so a
 * comparison costs O(n * k) rather than O(n^2) — bounded whether the two names
 * are similar or not.
 *
 * A row-minimum cutoff alone is not enough. It exits early only when EVERY
 * reachable cell in a row is already over the threshold, which maximally
 * different names reach on the third row but names sharing a long prefix never
 * reach at all — and a long shared prefix is the realistic shape, since stored
 * secret names look alike. So the two optimisations cover different shapes and
 * neither substitutes for the other:
 *
 *   5000 stored names, 100 requested, MAX_HINTED = 10, cells evaluated:
 *
 *                              60-char shared prefix   differing from char 1
 *     band + cutoff (shipped)             15,603,880                 600,000
 *     cutoff alone, no band              202,749,440               9,600,000
 *     band alone, no cutoff                15,700,000              15,700,000
 *
 * Read the columns, not the rows: the shared-prefix column is what the BAND
 * holds down (13x), and the differing-from-char-1 column is the only one that
 * moves when the CUTOFF goes (26x). Each column is pinned by its own test in
 * `secret-store.test.ts`; deleting the second as redundant would leave the row
 * cutoff with no regression test at all.
 */
export function editDistance(a: string, b: string): number {
  const s = a.toUpperCase();
  const t = b.toUpperCase();
  // Names have no length limit; keep the table small regardless.
  if (s.length > 64 || t.length > 64) return OVER;
  if (Math.abs(s.length - t.length) > NEAR_MISS_MAX) return OVER;

  let prev: number[] = new Array(t.length + 1).fill(OVER);
  for (let j = 0; j <= Math.min(t.length, NEAR_MISS_MAX); j++) prev[j] = j;

  for (let i = 1; i <= s.length; i++) {
    const cur: number[] = new Array(t.length + 1).fill(OVER);
    cur[0] = i <= NEAR_MISS_MAX ? i : OVER;
    const lo = Math.max(1, i - NEAR_MISS_MAX);
    const hi = Math.min(t.length, i + NEAR_MISS_MAX);
    // Derived from lo/hi rather than restated as a constant, so the count
    // cannot disagree with the loop it measures. Once per ROW, never per cell.
    cellsEvaluated += hi >= lo ? hi - lo + 1 : 0;
    let rowMin = cur[0];
    for (let j = lo; j <= hi; j++) {
      const v = Math.min(
        prev[j] + 1,
        cur[j - 1] + 1,
        prev[j - 1] + (s[i - 1] === t[j - 1] ? 0 : 1),
      );
      cur[j] = v > OVER ? OVER : v;
      if (cur[j] < rowMin) rowMin = cur[j];
    }
    // Every reachable cell already exceeds the threshold, so the final distance
    // cannot come back under it.
    if (rowMin > NEAR_MISS_MAX) return OVER;
    prev = cur;
  }
  return prev[t.length];
}

/**
 * The closest candidate to `miss` within NEAR_MISS_MAX, or undefined.
 *
 * Ties resolve to the first candidate in the order given, so callers control
 * determinism by controlling their candidate order rather than relying on a
 * sort that a future edit could make unstable.
 */
export function nearestMatch(miss: string, candidates: readonly string[]): string | undefined {
  let best: string | undefined;
  let bestDistance = OVER;
  for (const candidate of candidates) {
    const d = editDistance(miss, candidate);
    if (d < bestDistance) {
      bestDistance = d;
      best = candidate;
    }
  }
  return bestDistance <= NEAR_MISS_MAX ? best : undefined;
}
