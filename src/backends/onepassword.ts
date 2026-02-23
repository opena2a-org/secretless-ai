/**
 * 1Password backend — stores secrets in a 1Password vault using the `op` CLI.
 *
 * Each secret is stored as a Password item with:
 *   vault  = "Secretless" (configurable, auto-created on first write)
 *   title  = key (e.g. "mcp/claude-desktop/my-server/API_KEY")
 *   tag    = "secretless" (for filtering managed items)
 *   field  = password (the secret value)
 *
 * Prerequisites:
 *   - 1Password CLI v2+ installed (https://developer.1password.com/docs/cli)
 *   - Signed in via `op signin`, biometric unlock, or OP_SERVICE_ACCOUNT_TOKEN
 *
 * Security properties:
 *   - Secrets never touch the local filesystem (unlike local backend)
 *   - Cross-device sync via 1Password (unlike OS keychain, which is device-local)
 *   - Full audit trail in 1Password for enterprise visibility
 *   - Biometric unlock (Touch ID / Windows Hello) when available
 *   - Service account tokens for CI/CD automation
 *
 * Uses execFileSync (no shell) to prevent injection via secret values.
 */

import { execFileSync } from 'child_process';
import type { WritableSecretBackend, BackendHealth } from './types';

const DEFAULT_VAULT = 'Secretless';
const ITEM_TAG = 'secretless';

/** Minimal shape returned by `op item list --format json`. */
interface OpItem {
  id: string;
  title: string;
}

/** Shape returned by `op item get --fields password --format json`. */
interface OpFieldResult {
  value: string;
}

/** Shape returned by `op vault create/get --format json`. */
interface OpVault {
  id: string;
}

export class OnePasswordBackend implements WritableSecretBackend {
  readonly name = '1password';
  private readonly vaultName: string;
  private cachedVaultId: string | null = null;

  constructor(config?: Record<string, unknown>) {
    this.vaultName = (config?.vault as string) ?? DEFAULT_VAULT;
  }

  async store(key: string, value: string): Promise<void> {
    const vaultId = this.ensureVault();

    // Delete existing entry first (ignore errors if it doesn't exist)
    try {
      this.deleteByTitle(key, vaultId);
    } catch {
      // Entry didn't exist — that's fine
    }

    // Create new item. The password=VALUE field assignment is the standard
    // approach documented by 1Password for CLI automation.
    execFileSync('op', [
      'item', 'create',
      '--vault', vaultId,
      '--category', 'Password',
      '--title', key,
      '--tags', ITEM_TAG,
      `password=${value}`,
    ], { stdio: ['pipe', 'pipe', 'pipe'] });
  }

  async resolve(secretPath: string): Promise<Record<string, string>> {
    const vaultId = this.getVaultId();
    if (!vaultId) return {};

    const items = this.listItems(vaultId);
    const matching = items.filter(
      i => i.title === secretPath || i.title.startsWith(secretPath + '/'),
    );

    const results: Record<string, string> = {};
    for (const item of matching) {
      try {
        const value = this.getItemPassword(item.id, vaultId);
        if (value) {
          results[item.title] = value;
        }
      } catch {
        // Item exists in list but value can't be read — skip
      }
    }
    return results;
  }

  async delete(key: string): Promise<boolean> {
    const vaultId = this.getVaultId();
    if (!vaultId) return false;

    try {
      this.deleteByTitle(key, vaultId);
      return true;
    } catch {
      return false;
    }
  }

  async healthCheck(): Promise<BackendHealth> {
    const start = Date.now();
    try {
      execFileSync('op', ['account', 'get', '--format', 'json'], {
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      return {
        healthy: true,
        latencyMs: Date.now() - start,
        message: '1Password CLI authenticated',
      };
    } catch {
      return {
        healthy: false,
        latencyMs: Date.now() - start,
        message: '1Password CLI not authenticated. Run `op signin` or set OP_SERVICE_ACCOUNT_TOKEN.',
      };
    }
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  /**
   * Get or create the Secretless vault. Returns the vault ID.
   * Caches the vault ID for the lifetime of this backend instance.
   */
  private ensureVault(): string {
    const existing = this.getVaultId();
    if (existing) return existing;

    const out = execFileSync('op', [
      'vault', 'create', this.vaultName,
      '--format', 'json',
    ], { stdio: ['pipe', 'pipe', 'pipe'], encoding: 'utf-8' });

    const vault: OpVault = JSON.parse(out);
    this.cachedVaultId = vault.id;
    return vault.id;
  }

  /**
   * Look up the vault ID by name. Returns null if the vault doesn't exist
   * or the CLI is not authenticated.
   */
  private getVaultId(): string | null {
    if (this.cachedVaultId) return this.cachedVaultId;

    try {
      const out = execFileSync('op', [
        'vault', 'get', this.vaultName,
        '--format', 'json',
      ], { stdio: ['pipe', 'pipe', 'pipe'], encoding: 'utf-8' });

      const vault: OpVault = JSON.parse(out);
      this.cachedVaultId = vault.id;
      return vault.id;
    } catch {
      return null;
    }
  }

  /**
   * List all secretless-tagged items in the vault.
   * Returns an empty array if the vault is empty or on error.
   */
  private listItems(vaultId: string): OpItem[] {
    try {
      const out = execFileSync('op', [
        'item', 'list',
        '--vault', vaultId,
        '--tags', ITEM_TAG,
        '--format', 'json',
      ], { stdio: ['pipe', 'pipe', 'pipe'], encoding: 'utf-8' });

      const parsed = JSON.parse(out || '[]');
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }

  /**
   * Retrieve the password field value for a single item by ID.
   */
  private getItemPassword(itemId: string, vaultId: string): string {
    const out = execFileSync('op', [
      'item', 'get', itemId,
      '--vault', vaultId,
      '--fields', 'password',
      '--format', 'json',
    ], { stdio: ['pipe', 'pipe', 'pipe'], encoding: 'utf-8' });

    const field: OpFieldResult = JSON.parse(out);
    return field.value;
  }

  /**
   * Delete a single item by its title within the vault.
   * Throws if the item doesn't exist or can't be deleted.
   *
   * Uses `op item delete TITLE` — the CLI resolves titles within the
   * specified vault. Since secretless enforces unique titles (via
   * delete-before-create in store()), this is always unambiguous.
   */
  private deleteByTitle(title: string, vaultId: string): void {
    execFileSync('op', [
      'item', 'delete', title,
      '--vault', vaultId,
    ], { stdio: 'pipe' });
  }
}
