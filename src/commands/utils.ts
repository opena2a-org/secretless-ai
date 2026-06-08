// eslint-disable-next-line @typescript-eslint/no-var-requires
export const VERSION: string = require('../../package.json').version;

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
