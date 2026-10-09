/**
 * Rendering text that came out of the scanned tree.
 *
 * A file or directory name in a scan report is a name from the repository
 * being scanned, so whoever wrote the repository chose it. The same holds for
 * an excerpt of a file's content. Written straight to a terminal, two things
 * go wrong:
 *
 * A line feed SPLITS the line. A config file named
 * `sec<LF>  Scan one: npx secretless-ai scan elsewhere.json` printed a second
 * `Scan one:` line under the real one, indistinguishable from the scanner's
 * own output.
 *
 * An ESC byte is worse than cosmetic: `ESC [ 2 K` erases a line and
 * `ESC [ 1 A` moves the cursor up, so an excerpt could overwrite the report
 * line describing it, and an OSC sequence in a name reaches the terminal's own
 * command channel.
 *
 * So these characters are made VISIBLE rather than dropped. Dropping turns two
 * different names into one, and a shortened name in a report is a name that
 * does not exist. Escaping keeps each name on one line and keeps the report a
 * faithful description of what was found.
 *
 * The alphabet is hackmyagent's (`\n`, `\t`, `\e`, `\0`, `\r`, `\xHH`,
 * `\uHHHH`, `\u{…}`), so a character both tools escape renders the same way in
 * both.
 *
 * This runs on the text AS PRINTED, after detection and after redaction. No
 * detector and no redactor reads escaped text: escaping first would change the
 * bytes a pattern's gate sees and the span a redactor masks. `--json` output
 * keeps its own escaping and does not pass through here.
 */
import * as path from 'path';

/**
 * C0, DEL, C1 (`\p{Cc}`), every format character (`\p{Cf}`: the bidi
 * embeddings, overrides and isolates, the zero-width characters, the tag
 * block), the two Unicode line separators, and the characters that render as
 * nothing or as a blank without being Cc or Cf: the combining grapheme joiner
 * (U+034F), the Hangul fillers, the Khmer inherent vowels (U+17B4, U+17B5), the
 * Mongolian free variation selectors and vowel separator (U+180B to U+180F),
 * the blank Braille pattern (U+2800) and the variation selectors. Two names
 * that differ only by one of these print alike unless it is escaped.
 *
 * Built from a string of escapes rather than a regex literal: a literal control
 * byte inside a character class is invisible in every diff and every editor
 * that would review it.
 *
 * One exemption: a variation selector that FOLLOWS a pictograph is emoji
 * presentation, and the character it modifies is what the reader sees.
 * Escaping those would turn every emoji with a selector into an escape for no
 * gain. A variation selector after anything else has nothing visible to modify
 * and is escaped.
 */
const DISPLAY_HAZARD = new RegExp(
  '[\\p{Cc}\\p{Cf}\\p{Zl}\\p{Zp}\\u{034F}\\u{115F}\\u{1160}\\u{17B4}\\u{17B5}'
  + '\\u{180B}-\\u{180F}\\u{2800}\\u{3164}\\u{FFA0}]'
  + '|(?<!\\p{Extended_Pictographic})[\\u{FE00}-\\u{FE0F}\\u{E0100}-\\u{E01EF}]',
  'gu',
);

/** Keyed by code point, for the same reason: no control characters in source. */
const NAMED: Record<number, string> = {
  0x00: '\\0',
  0x09: '\\t',
  0x0a: '\\n',
  0x0d: '\\r',
  0x1b: '\\e',
};

/**
 * One code point, rendered visibly. Astral code points take `\u{…}` braces:
 * U+E0041 is five hex digits where `\uHHHH` holds four, so without braces it
 * would read the same as U+E004 followed by `1`.
 */
function escapeCodePoint(code: number): string {
  const named = NAMED[code];
  if (named) return named;
  if (code <= 0xff) return `\\x${code.toString(16).padStart(2, '0')}`;
  return code <= 0xffff
    ? `\\u${code.toString(16).padStart(4, '0')}`
    : `\\u{${code.toString(16)}}`;
}

/**
 * Make invisible and terminal-controlling characters visible, so one rendered
 * line stays one line and says what is really there.
 *
 * Every replaced character maps to printable ASCII, so the result cannot split
 * a line, move the cursor, or change the terminal's state. Text with no such
 * characters is returned unchanged, which keeps every ordinary report
 * byte-identical.
 */
export function escapeForDisplay(text: string): string {
  return text.replace(DISPLAY_HAZARD, (ch) => escapeCodePoint(ch.codePointAt(0) ?? 0));
}

/** True when `escapeForDisplay` would change `text`, i.e. what is shown is a rendering. */
export function hasDisplayHazard(text: string): boolean {
  DISPLAY_HAZARD.lastIndex = 0;
  return DISPLAY_HAZARD.test(text);
}

/**
 * A path with `/` between its parts on every platform.
 *
 * On Windows `\` is the separator and no name can hold it. Escaped as a name
 * character it was doubled before an escape letter, so `src\new.ts` printed as
 * `src\\new.ts`. On POSIX a backslash is a character a name can hold, and
 * turning it into `/` names a different path: `n\x.txt` became `n/x.txt`.
 * So only the platform's own separator is replaced. `sep` is a parameter so
 * both platforms can be tested on either.
 */
export function withSlashSeparators(p: string, sep: string = path.sep): string {
  return sep === '/' ? p : p.split(sep).join('/');
}

/**
 * The same escaping for a BARE name, and one-to-one.
 *
 * `escapeForDisplay` alone would render a directory literally named `dir\nx`
 * (backslash, then `n`) exactly like one named `dir<LF>x`. A backslash only
 * needs escaping when it could be READ as one of the escapes above, so only
 * those are doubled: a backslash before `0`, `t`, `n`, `r`, `e`, `x`, `u`,
 * another backslash, or a character that is about to become an escape.
 * `a\b.txt` renders as itself; `dir\nx` renders as `dir\\nx`. A Windows
 * separator is printed as `/` first (see `withSlashSeparators`).
 *
 * Use this for a name printed on its own, and `escapeForDisplay` for an
 * excerpt: doubling is only correct on a raw name.
 */
const AMBIGUOUS_AFTER_BACKSLASH = new Set(['0', 't', 'n', 'r', 'e', 'x', 'u', '\\']);

export function escapePathForDisplay(p: string, sep: string = path.sep): string {
  // Two passes, and the order matters. Doubling is decided per character with
  // a one-character lookahead; escaping is decided over the whole string,
  // because the pictograph exemption is a lookbehind that a per-character test
  // cannot see.
  const chars = [...withSlashSeparators(p, sep)];
  let doubled = '';
  for (let i = 0; i < chars.length; i++) {
    const ch = chars[i];
    if (ch !== '\\') {
      doubled += ch;
      continue;
    }
    const next = chars[i + 1];
    // A trailing backslash cannot be read as an escape. A backslash before a
    // hazard is ambiguous whatever the exemption says, because the backslash
    // itself now stands between the pictograph and the selector.
    const ambiguous = next !== undefined
      && (AMBIGUOUS_AFTER_BACKSLASH.has(next) || hasDisplayHazard(next));
    doubled += ambiguous ? '\\\\' : '\\';
  }
  return escapeForDisplay(doubled);
}

/**
 * A name that cannot be printed as itself, escaped and quoted as one word:
 * `$'...'`, the shell's quoting for a string with escapes in it.
 *
 * A list prints `<path>: <reason>`. Escaped but bare, a name has no visible
 * end, so a `: ` inside it reads as that separator: a directory named
 * `.a<ESC>: test directory (--include-tests)` printed as
 * `.a\e: test directory (--include-tests): hidden directory`. Inside the
 * quotes every backslash is doubled and a single quote is written `\'`, so
 * read left to right, the first `'` that is not part of a `\'` ends the name.
 * The other escapes are the ones above.
 *
 * Only for a name that `hasDisplayHazard` flags. A name that prints as itself
 * is quoted for pasting instead (`shellQuote`), and this form is not offered as
 * a command operand: it describes the name.
 */
export function quotePathForDisplay(p: string, sep: string = path.sep): string {
  let body = '';
  for (const ch of withSlashSeparators(p, sep)) {
    body += ch === '\\' ? '\\\\' : ch === "'" ? "\\'" : ch;
  }
  return `$'${escapeForDisplay(body)}'`;
}

/**
 * An excerpt of a file's content, as lines to print one by one under the
 * caller's own prefix, each with its hazards escaped.
 *
 * A line break in an excerpt is a line break the reader should see, so it
 * becomes a new line under the tool's prefix rather than a `\n`; anything the
 * excerpt prints on a line of its own then still sits under that prefix and
 * cannot pass for the tool's own output. A carriage return that does not end
 * a line would move the cursor back over the prefix, so it is escaped like any
 * other control character.
 */
export function excerptLinesForDisplay(text: string): string[] {
  return text.split(/\r?\n/).map(escapeForDisplay);
}
