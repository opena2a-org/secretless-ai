/**
 * JSON parsing for input the broker acts on, refusing a duplicated member name
 * before `JSON.parse` can collapse it.
 *
 * `JSON.parse` keeps the last copy of a repeated member and hands nothing
 * downstream that says there was more than one, so the scan has to run on the
 * raw text first. The scanner is `firstDuplicateMember` from
 * `@opena2a/atx-verify`, the one the policy file and `/grant` already use: it
 * compares names after escape decoding and case folding, at every depth, and
 * is strict about structure where `JSON.parse` is not.
 *
 * The outcomes are kept apart so each caller can answer them differently. A
 * scanner that will not load is an installation fault on our side, not a
 * malformed input, and no outcome falls back to a bare `JSON.parse`: a caller
 * that gets `scanner-unavailable` must withhold, never parse anyway.
 */

export type StrictJsonResult =
  | { ok: true; value: unknown }
  | { ok: false; reason: 'scanner-unavailable'; detail: string }
  | { ok: false; reason: 'duplicate-member'; member: string }
  | { ok: false; reason: 'invalid-json' };

export async function parseJsonRefusingDuplicates(text: string): Promise<StrictJsonResult> {
  // Dynamic import: @opena2a/atx-verify is ESM-only and this package is CJS.
  let firstDuplicateMember: (text: string) => string | null;
  try {
    ({ firstDuplicateMember } = await import('@opena2a/atx-verify'));
  } catch (err) {
    return {
      ok: false,
      reason: 'scanner-unavailable',
      detail: err instanceof Error ? err.message : String(err),
    };
  }

  let member: string | null;
  try {
    member = firstDuplicateMember(text);
  } catch {
    // StrictParseError: not a single well-formed JSON value the scanner can
    // vouch for. Refused here so the accept-set of the parse and of the check
    // stay identical.
    return { ok: false, reason: 'invalid-json' };
  }
  if (member !== null) {
    return { ok: false, reason: 'duplicate-member', member };
  }

  // The scanner is lax on scalar tokens, so JSON.parse can still refuse text
  // the scan passed.
  try {
    return { ok: true, value: JSON.parse(text) };
  } catch {
    return { ok: false, reason: 'invalid-json' };
  }
}
