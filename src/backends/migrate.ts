/**
 * Secret migration — moves secrets between backends.
 *
 * Resolves all secrets from the source backend under a given prefix,
 * stores each in the destination backend, and optionally deletes from source.
 */

import type { WritableSecretBackend } from './types';

export interface MigrateOptions {
  /** Delete successfully migrated secrets from the source backend. Default: false. */
  deleteFromSource?: boolean;
  /** Secret path prefix to migrate (e.g. 'mcp'). Default: 'mcp'. */
  prefix?: string;
}

export interface MigrateResult {
  migrated: number;
  failed: number;
  errors: Array<{ key: string; message: string }>;
}

/**
 * Migrate secrets from one backend to another.
 *
 * @param source      - Backend to read secrets from
 * @param destination - Backend to write secrets to
 * @param options     - Migration options
 */
export async function migrateSecrets(
  source: WritableSecretBackend,
  destination: WritableSecretBackend,
  options?: MigrateOptions,
): Promise<MigrateResult> {
  const prefix = options?.prefix ?? 'mcp';
  const deleteFromSource = options?.deleteFromSource ?? false;

  const secrets = await source.resolve(prefix);
  const result: MigrateResult = { migrated: 0, failed: 0, errors: [] };

  for (const [key, value] of Object.entries(secrets)) {
    try {
      await destination.store(key, value);
      result.migrated++;

      if (deleteFromSource) {
        await source.delete(key);
      }
    } catch (err) {
      result.failed++;
      result.errors.push({
        key,
        message: err instanceof Error ? err.message : String(err),
      });
    }
  }

  return result;
}
