/**
 * Shell environment export — outputs stored secrets as shell export statements.
 *
 * Usage:
 *   eval "$(secretless-ai env)"          # Export all secrets to current shell
 *   eval "$(secretless-ai env --only NPM_TOKEN,GITHUB_TOKEN)"  # Specific secrets
 *
 * Designed to be added to shell profiles (~/.zshenv, ~/.bashrc) so secrets
 * stored in the vault are automatically available as env vars without manual
 * export lines.
 *
 * Security:
 *   - Output goes only to a TTY or to a shell `eval` consumer; AI tools never capture it.
 *   - Values are single-quoted to prevent shell expansion
 *   - The eval pattern means secrets never touch disk as plaintext
 */

import { SecretStore } from './secret-store';
import type { SecretStoreOptions } from './secret-store';

export interface EnvOptions extends SecretStoreOptions {
  /** Only export these specific secret names. */
  only?: string[];
}

/**
 * A POSIX shell variable name: a letter or underscore followed by letters,
 * digits, or underscores. Stored secret names are more permissive than this
 * (they also allow `-`), so a name like `vault-name` is a valid secret but an
 * invalid shell identifier. Exporting it as `export vault-name=...` makes the
 * shell reject the whole `eval`, which breaks every command in profiles that
 * run `eval "$(secretless-ai env)"`. We skip such names instead.
 */
const SHELL_IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]*$/;

export function isValidShellIdentifier(name: string): boolean {
  return SHELL_IDENTIFIER.test(name);
}

/**
 * Generate shell export statements for stored secrets.
 * Returns the export script as a string.
 *
 * Secret names that are not valid shell identifiers (e.g. they contain a `-`)
 * are skipped — one such name would otherwise make the entire `eval` fail and
 * break every shell command. The skipped names are reported as a leading shell
 * comment, which is a no-op inside `eval` but visible on direct invocation, so
 * the secret stays loadable via `secretless-ai run` / `--only` and the user is
 * told how to fix it without any secret value being exposed.
 */
export async function generateEnvExports(options?: EnvOptions): Promise<string> {
  const store = new SecretStore(options);
  const secrets = await store.loadSecrets(options?.only);

  const lines: string[] = [];
  const skipped: string[] = [];
  for (const [name, value] of Object.entries(secrets)) {
    if (!isValidShellIdentifier(name)) {
      skipped.push(name);
      continue;
    }
    // Single-quote the value and escape any embedded single quotes
    // using the standard shell pattern: replace ' with '\''
    const escaped = value.replace(/'/g, "'\\''");
    lines.push(`export ${name}='${escaped}'`);
  }

  if (skipped.length > 0) {
    // A shell comment: harmless inside `eval`, visible on direct invocation.
    lines.unshift(
      `# secretless: skipped ${skipped.length} secret${skipped.length === 1 ? '' : 's'} ` +
        `with a name that is not a valid shell variable: ${skipped.join(', ')}. ` +
        `Rename to export (e.g. secretless-ai secret set NEW_NAME), or use secretless-ai run -- <cmd>.`,
    );
  }

  return lines.join('\n');
}

/**
 * Generate the shell profile hook line for auto-loading secrets.
 * Returns the eval line to add to ~/.zshenv or ~/.bashrc.
 */
export function getShellHookLine(): string {
  return 'eval "$(secretless-ai env 2>/dev/null)"';
}

/**
 * Marker comment used to identify secretless-managed lines in shell profiles.
 */
export const SHELL_HOOK_MARKER = '# secretless-ai: auto-load secrets from vault';
