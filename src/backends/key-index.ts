/**
 * The name index both OS-keychain backends keep beside the keychain itself.
 *
 * The OS keychain has no "list everything this tool stored" query, so the
 * backends record the names they wrote in a plain JSON array and enumerate from
 * it. That makes this file the answer to "what secrets exist" — and an
 * unreadable answer used to be returned as an empty one.
 *
 * `catch { return [] }` is correct for exactly one cause, a file that is not
 * there yet, and wrong for every other. A truncated or malformed index made
 * `secret list` print nothing, `resolve` return nothing and `run` inject
 * nothing, all with exit 0, over a keychain that still held every secret (#104).
 */

import * as fs from 'fs';

function unreadableIndexError(indexPath: string, reason: string): Error {
  return new Error(
    [
      'The secret name index could not be read.',
      '',
      '  Nothing was listed. Refusing to report an empty keychain, because an',
      '  empty index and an unreadable one are not the same thing.',
      '',
      `  Index:   ${indexPath}`,
      `  Reason:  ${reason}`,
      '',
      '  Your secrets are in the OS keychain and are untouched. This file only',
      '  records which names belong to this tool.',
      '',
      `  Verify:  cat ${indexPath}`,
      '  Fix:     repair it — it is a JSON array of names, e.g. ["secret/API_KEY"]',
      '           or delete it and re-add names with  secretless-ai secret set NAME',
    ].join('\n'),
  );
}

/**
 * Read the index, or throw.
 *
 * Returns [] only when the file does not exist. Every other failure is a state
 * this function cannot describe, so it does not try.
 */
export function readKeyIndex(indexPath: string): string[] {
  let raw: string;
  try {
    raw = fs.readFileSync(indexPath, 'utf-8');
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return [];
    throw unreadableIndexError(indexPath, (err as Error).message);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    // The parse error quotes the input, and the input is a list of the user's
    // secret names. Not shown.
    throw unreadableIndexError(indexPath, 'not valid JSON');
  }

  if (!Array.isArray(parsed)) {
    throw unreadableIndexError(indexPath, 'not a JSON array');
  }
  // Filtering non-strings out would silently drop a secret from the listing,
  // which is the same fail-open in a smaller shape.
  if (!parsed.every((k) => typeof k === 'string')) {
    throw unreadableIndexError(indexPath, 'contains an entry that is not a name');
  }
  return parsed as string[];
}
