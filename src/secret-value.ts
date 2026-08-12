/**
 * What a stored secret is allowed to be, and how to describe one without
 * showing it.
 *
 * A 40-character hex token pasted at the interactive prompt was stored as 19
 * bytes containing control characters and U+FFFD — the shape of a bracketed
 * paste whose escape sequences landed inside the captured value. Nothing
 * checked, so nothing warned, and the corruption surfaced much later as a
 * TypeError inside an unrelated consumer building an HTTP header (#104).
 *
 * The check belongs at the store boundary rather than in the prompt: `set`,
 * `import` and the MCP write path all end at `setSecret`, and a rule enforced
 * in one of three places is a rule with two ways around it.
 */

/**
 * Control characters a real credential can legitimately contain.
 *
 * Newline is the reason this list is not empty — PEM keys and JSON service
 * account blobs are multi-line and are piped in whole. Carriage return comes
 * with them from Windows-authored files, and tab appears in some pasted blobs.
 */
const ALLOWED_CONTROLS = new Set(['\t', '\n', '\r']);

/** U+FFFD. Its presence means bytes were already lost decoding the input. */
const REPLACEMENT_CHAR = '�';

export interface SecretValueProblem {
  /** Machine-readable cause, for callers that branch on it. */
  kind: 'null-byte' | 'replacement-char' | 'control-char';
  /** Human-readable name of the offending character. Never the value. */
  found: string;
  /** 1-based character position, so a user can see where the paste went wrong. */
  at: number;
}

/**
 * The first thing wrong with this value, or null if nothing is.
 *
 * Order matters only for the message: a value can trip several of these and the
 * earliest position is the most useful thing to report.
 */
export function findSecretValueProblem(value: string): SecretValueProblem | null {
  for (let i = 0; i < value.length; i++) {
    const ch = value[i];
    if (ch === '\0') return { kind: 'null-byte', found: 'a null byte', at: i + 1 };
    if (ch === REPLACEMENT_CHAR) {
      return { kind: 'replacement-char', found: 'U+FFFD (replacement character)', at: i + 1 };
    }
    const code = ch.charCodeAt(0);
    const isControl = code < 0x20 || code === 0x7f;
    if (isControl && !ALLOWED_CONTROLS.has(ch)) {
      const name = code === 0x1b ? 'an escape character (0x1B)' : `a control character (0x${code.toString(16).toUpperCase().padStart(2, '0')})`;
      return { kind: 'control-char', found: name, at: i + 1 };
    }
  }
  return null;
}

/**
 * Error for a value that cannot be stored.
 *
 * Names the secret, the character and where it is. Never the value — the point
 * of rejecting it is that it is a credential, mangled or not.
 */
export function unstorableSecretError(name: string, problem: SecretValueProblem): Error {
  const cause = problem.kind === 'replacement-char'
    ? [
      '  U+FFFD is what a decoder writes when it has already lost the original',
      '  bytes, so the value cannot be recovered from what was captured.',
    ]
    : [
      '  Almost no real credential contains one. This is usually a paste that',
      '  captured your terminal\'s bracketed-paste escape sequences along with',
      '  the value.',
    ];

  return new Error(
    [
      `"${name}" was not stored: the value contains ${problem.found} at character ${problem.at}.`,
      '',
      ...cause,
      '',
      '  Verify:  secretless-ai secret list',
      `  Fix:     secretless-ai secret set ${name}=<value>   (as an argument, not a paste)`,
      '           or pipe it:  cat token.txt | secretless-ai secret set ' + name,
    ].join('\n'),
  );
}

/**
 * A one-line shape summary: length and character class, never content.
 *
 * Printed on every successful write so a bad capture is visible at the moment
 * it happens rather than at first use. The 40-character token in #104 was
 * stored as 19 bytes; "19 chars" alone would have said so.
 */
export function describeSecretShape(value: string): string {
  const chars = `${value.length} char${value.length === 1 ? '' : 's'}`;
  if (value.includes('\n')) return `${chars}, multi-line`;
  if (/^[0-9a-f]+$/i.test(value)) return `${chars}, hex`;
  // Alphanumeric is checked before base64, and base64 requires a character
  // only base64 has. Every alphanumeric string whose length is a multiple of
  // four is also valid base64, so testing base64 first labels an ordinary
  // 32-character API key as base64 — a guess dressed as a measurement.
  if (/^[A-Za-z0-9]+$/.test(value)) return `${chars}, alphanumeric`;
  if (/^[A-Za-z0-9+/]+={0,2}$/.test(value) && value.length % 4 === 0) return `${chars}, base64`;
  if (/^[\x20-\x7e]+$/.test(value)) return `${chars}, printable ASCII`;
  return chars;
}
