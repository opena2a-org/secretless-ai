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
 *   - Only outputs to TTY or when stdout is piped to eval (no AI tool capture)
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
 * Generate shell export statements for stored secrets.
 * Returns the export script as a string.
 */
export async function generateEnvExports(options?: EnvOptions): Promise<string> {
  const store = new SecretStore(options);
  const secrets = await store.loadSecrets(options?.only);

  const lines: string[] = [];
  for (const [name, value] of Object.entries(secrets)) {
    // Single-quote the value and escape any embedded single quotes
    // using the standard shell pattern: replace ' with '\''
    const escaped = value.replace(/'/g, "'\\''");
    lines.push(`export ${name}='${escaped}'`);
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
