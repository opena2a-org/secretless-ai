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

/**
 * Characters that may continue a credential past the end of its pattern match.
 *
 * Deliberately NARROWER than the alphabet real credentials can use: `+`, `/` and
 * `=` are excluded even though base64 secrets contain them. Two of the three
 * callers here REWRITE THE USER'S FILE (`clean` a transcript, `clean-history`
 * a shell history), so over-extending is not a harmless wider mask — it deletes
 * the user's own content. `/` is the dangerous one: a token appearing inside a
 * URL or path would swallow the rest of the path.
 *
 * The residual limit is recorded rather than hidden: a base64 value whose
 * overshoot begins with `+`, `/` or `=` still keeps that character. Closing that
 * needs the pattern's quantifier opened, which is a DETECTION change and is
 * scoped separately.
 */
const CREDENTIAL_TAIL = /[A-Za-z0-9_-]/;

/**
 * Replace every match of `regex` in `text` with `label`, extending the
 * replacement across any credential-shaped characters that FOLLOW the match.
 *
 * Why this exists: a redactor that replaces exactly what the detector matched is
 * only as wide as the detector, and much of `patterns.ts` uses FIXED quantifiers
 * (`ghp_[a-zA-Z0-9]{36}`, `AKIA[0-9A-Z]{16}`, `AIza[...]{35}`). A value one
 * character longer than the pattern's fixed length matched a PREFIX, and the
 * unmatched tail survived into whatever the caller did next. Measured on 0.22.0:
 * `clean-history` reported `History cleaned.` while leaving 11 four-character
 * runs of a `ghp_` token in `~/.bash_history`, and `diff` printed most of an
 * over-length credential to stdout under a `[... REDACTED]` label.
 *
 * This is the same lesson as `leaksAny` above, applied to the replacement side:
 * the detector's reach is not the credential's length, so the redactor must not
 * take the match as the boundary. It is a REDACTION change only — no pattern is
 * altered, so nothing new is detected and no scan result changes.
 *
 * `preferCaptureGroup` keeps the existing name-gated behaviour: patterns like
 * `AWS_SECRET_ACCESS_KEY = "..."` match ACROSS the variable name, so replacing
 * the whole match erased the name and left a bare quote. When the pattern
 * captures the value in group 1, only from that group onward is replaced.
 */
export function redactMatches(
  text: string,
  regex: RegExp,
  label: string,
  opts?: { preferCaptureGroup?: boolean },
): string {
  const flags = regex.flags.includes('g') ? regex.flags : regex.flags + 'g';
  const scanner = new RegExp(regex.source, flags);
  let out = '';
  let cursor = 0;
  let m: RegExpExecArray | null;

  while ((m = scanner.exec(text)) !== null) {
    // A zero-length match would leave lastIndex where it is and spin forever.
    if (m[0].length === 0) {
      scanner.lastIndex++;
      continue;
    }

    const matchStart = m.index;
    let cutFrom = matchStart;

    if (opts?.preferCaptureGroup) {
      const group = typeof m[1] === 'string' ? m[1] : undefined;
      // indexOf, not a group index: the goal is to keep the gating prefix the
      // user needs to see (the variable name), and the value's offset inside
      // the match is what identifies where that prefix ends.
      if (group && group.length > 0) {
        const rel = m[0].indexOf(group);
        if (rel > 0) cutFrom = matchStart + rel;
      }
    }

    // Extend past the match across anything that could still be the credential.
    let cutTo = matchStart + m[0].length;
    while (cutTo < text.length && CREDENTIAL_TAIL.test(text[cutTo])) cutTo++;

    out += text.slice(cursor, cutFrom) + label;
    cursor = cutTo;
    // The tail is consumed, so continue scanning after it rather than from the
    // match end — otherwise the same characters are re-examined.
    scanner.lastIndex = cutTo;
  }

  return cursor === 0 ? text : out + text.slice(cursor);
}
