/**
 * Keeping secret values out of error messages.
 *
 * Error messages are the tool's own worst leak surface: they are printed to
 * stderr, stderr is what CI captures, and a failing command is exactly what a
 * user pastes into a chat window to ask why it failed. Every path that holds a
 * resolved secret and can throw goes through here.
 *
 * The hard part is not the scrub, it is the detector. Runtimes do not embed a
 * value verbatim — they escape it and they truncate it. Measured against the
 * two throws this tool actually hits:
 *
 *   spawn, value containing a NUL byte
 *     Received 'sk-fake-DEADBEEF\x00-tail'      <- \x00 is four literal chars
 *   spawn, value longer than ~120 chars
 *     Received 'sk-live-AAAA...'                <- truncated, then "..."
 *   JSON.parse of a decrypted store
 *     Unexpected token 's', "sk-live-NO"... is not valid JSON
 *
 * In ALL of those, `message.includes(value)` is false. A detector built on
 * whole-value containment reports "no leak" over a message displaying most of
 * the credential, and a redactor built on whole-value replacement replaces
 * nothing. So the detector works on RUNS: any window of the value long enough
 * to matter, appearing anywhere in the text, is a leak.
 *
 * When the detector fires, the detail is dropped rather than trimmed. A partial
 * scrub is the failure mode, not the fix — the residue is what leaks.
 */

/**
 * Shortest run of a secret's own characters that counts as a leak.
 *
 * Four, matching the floor the Keychain backend has used since #108. Below it,
 * a secret containing a common fragment would blank every message the tool
 * produces. Above it, a truncated value gets through. A false positive here
 * costs a vaguer error; a false negative costs the credential.
 */
const MIN_LEAK_RUN = 4;

/**
 * True if `text` still exposes any of `values` — whole, escaped, or truncated.
 *
 * Whole-value containment is checked first and at any length, so a secret
 * shorter than the run floor is still caught outright.
 */
export function leaksAny(text: string, values: readonly string[]): boolean {
  if (!text) return false;
  for (const value of values) {
    if (!value) continue;
    if (text.includes(value)) return true;
    for (let i = 0; i + MIN_LEAK_RUN <= value.length; i++) {
      if (text.includes(value.slice(i, i + MIN_LEAK_RUN))) return true;
    }
  }
  return false;
}

/**
 * Replace whole occurrences of each value with `[REDACTED]`.
 *
 * Longest first: a shorter secret that happens to be a substring of a longer
 * one would otherwise cut the longer one in half and leave both fragments.
 * This is the cheap pass that keeps ordinary messages readable; `scrubOrDrop`
 * is what makes the result safe.
 */
export function redactValues(text: string, values: readonly string[]): string {
  let out = text;
  for (const value of [...values].filter(Boolean).sort((a, b) => b.length - a.length)) {
    out = out.split(value).join('[REDACTED]');
  }
  return out;
}

/**
 * Scrub `text`, and return '' if anything survives.
 *
 * The empty string is the signal that there is no safe detail to show. Callers
 * keep their own framing — which names the secret and what to do — and simply
 * omit the underlying message.
 */
export function scrubOrDrop(text: string, values: readonly string[]): string {
  const scrubbed = redactValues(text, values);
  return leaksAny(scrubbed, values) ? '' : scrubbed;
}
