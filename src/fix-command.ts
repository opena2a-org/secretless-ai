import { CLI } from './commands/utils';

/**
 * A secret name for the user to fill in: the `<name>` a Fix prints, or another
 * `<word>` spelling of it, such as the `<names>` a usage line prints. No store
 * or push target accepts '<' or '>' in a name.
 */
export const PLACEHOLDER_NAME = /^<[A-Za-z][A-Za-z0-9_-]*>$/;

/** What a Fix prints in place of a name it cannot offer. */
export const NAME_PLACEHOLDER = '<name>';

/**
 * Secret names a Fix prints as one word, joined by ','. `accepts` is the rule
 * of the command the Fix runs; a name it refuses is printed as `<name>`, so
 * the line is not refused for that name, and a placeholder stays as given.
 */
export interface FixNames {
  names: readonly string[];
  accepts: (name: string) => boolean;
}

export type FixWord = string | FixNames;

/**
 * `word` as one word of a POSIX shell: as given when no character in it means
 * anything to a shell, else in single quotes. Unquoted, a shell reads
 * `<name>,a_b` as input from a file `name` and output to a file `,a_b`.
 */
export function shellQuote(word: string): string {
  if (/^[A-Za-z0-9_,./:@+-][A-Za-z0-9_,./:=@+-]*$/.test(word)) return word;
  return `'${word.replace(/'/g, "'\\''")}'`;
}

/**
 * The command a `Fix:` line gives, as it runs when pasted into a shell:
 * `prefix`, the CLI as the user calls it, then each word quoted for a POSIX
 * shell. Each name of a `FixNames` word is checked by its rule and quoted on
 * its own, so `'<name>',a_b` reads as one word.
 */
export function fixCommand(words: readonly FixWord[], prefix: string = CLI): string {
  const printed = words.map((word) => (typeof word === 'string'
    ? shellQuote(word)
    : word.names
      .map((name) => shellQuote(PLACEHOLDER_NAME.test(name) || word.accepts(name) ? name : NAME_PLACEHOLDER))
      .join(',')));
  return [prefix, ...printed].join(' ');
}
