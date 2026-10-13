// eslint-disable-next-line @typescript-eslint/no-var-requires
export const VERSION: string = require('../../package.json').version;

/**
 * What the package says it does: the `description` in package.json, which a
 * test holds to the README's opening paragraph. Top-level help prints it, so
 * the README, the registry listing and `--help` say the same sentences.
 */
// eslint-disable-next-line @typescript-eslint/no-var-requires
export const DESCRIPTION: string = require('../../package.json').description;

/**
 * Command-invocation prefix used in all user-facing citations (help text,
 * error hints). Defaults to `npx secretless-ai` — the canonical standalone
 * invocation. When secretless is embedded under another CLI (e.g. opena2a-cli
 * exposes it as `opena2a secrets <verb>`), that host sets SECRETLESS_CLI_PREFIX
 * to its own full command path so citations render natively (`opena2a secrets
 * scan`) instead of leaking the standalone `npx secretless-ai scan`.
 */
export const CLI: string = process.env.SECRETLESS_CLI_PREFIX ?? 'npx secretless-ai';

/**
 * Bare form of the prefix for terse error hints (no `npx` wrapper). When
 * SECRETLESS_CLI_PREFIX is set we reuse it verbatim; otherwise we fall back to
 * the bare binary name `secretless-ai`.
 */
export const CLI_BARE: string = process.env.SECRETLESS_CLI_PREFIX ?? 'secretless-ai';

/**
 * True when secretless is running embedded under a host CLI. Used to suppress
 * the standalone `Secretless v<version>` brand+version banner, which would be
 * misleading under the host's umbrella (it shows secretless's own version, not
 * the host's).
 */
export const IS_EMBEDDED: boolean = process.env.SECRETLESS_CLI_PREFIX != null;

/** Help lines stay inside an 80-column terminal, counting their indent (4 spaces for notes). */
export const NOTE_WIDTH = 76;

/**
 * Pack `items` into lines no wider than NOTE_WIDTH. The first line starts with
 * `lead`, the rest with `indent`; pass both the same length. An item is never
 * split, so one wider than the limit gets a line of its own.
 */
export function wrapList(items: readonly string[], indent: string, sep = ' ', lead = indent): string[] {
  const lines: string[] = [];
  let line = '';
  for (const item of items) {
    const next = line ? `${line}${sep}${item}` : item;
    if (line && indent.length + next.length > NOTE_WIDTH) {
      lines.push((lines.length ? indent : lead) + line);
      line = item;
    } else {
      line = next;
    }
  }
  if (line) lines.push((lines.length ? indent : lead) + line);
  return lines;
}

/** Format seconds into a human-readable uptime string. */
export function formatUptime(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const secs = seconds % 60;
  if (minutes < 60) return `${minutes}m ${secs}s`;
  const hours = Math.floor(minutes / 60);
  const mins = minutes % 60;
  if (hours < 24) return `${hours}h ${mins}m`;
  const days = Math.floor(hours / 24);
  const hrs = hours % 24;
  return `${days}d ${hrs}h`;
}

export function formatRemainingTime(seconds: number): string {
  if (seconds <= 0) return 'expired';
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  const hours = Math.floor(seconds / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  return `${hours}h ${mins}m`;
}

/**
 * The one layout for an error a command prints in place of its result: a
 * blank line, `Error:` and the message's first line, every further line
 * indented two spaces, and a blank line. A line the message already indents
 * (the Verify and Fix lines most messages carry) keeps its own indent rather
 * than being pushed to four, and a line that carries none still lands
 * indented, never at column 0. `console.error(formatCommandError(err))`.
 */
export function formatCommandError(err: unknown): string {
  const message = err instanceof Error ? err.message : String(err);
  const [first, ...rest] = message.split('\n');
  const body = rest.map((line) => (line === '' || /^\s/.test(line) ? line : `  ${line}`));
  return ['', `  Error: ${first}`, ...body, ''].join('\n');
}
