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
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import type { WritableSecretBackend, BackendHealth } from './types';

const DEFAULT_VAULT = 'Secretless';
const ITEM_TAG = 'secretless';
const DEFAULT_OP_TIMEOUT_MS = 30_000;

/**
 * What `op` actually reported, without our own `Command failed: ...` argv echo.
 * Returns an indented block ending in a newline, or empty when there is nothing
 * useful to show.
 */
function opStderr(e: { stderr?: unknown; message?: string }): string {
  const raw = typeof e?.stderr === 'string' && e.stderr.trim()
    ? e.stderr
    : (e?.message ?? '');
  const kept = String(raw)
    .split('\n')
    .filter(line => line.trim() && !/^\s*Command failed:/.test(line))
    .map(line => `  ${line.trim()}`);
  return kept.length ? `${kept.join('\n')}\n` : '';
}

/** Per-invocation ceiling for `op`, overridable for slow approval flows. */
function opTimeoutMs(): number {
  const raw = Number(process.env.SECRETLESS_OP_TIMEOUT_MS);
  return Number.isFinite(raw) && raw > 0 ? raw : DEFAULT_OP_TIMEOUT_MS;
}

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
    const vault = (config?.vault as string) ?? DEFAULT_VAULT;
    if (!/^[a-zA-Z0-9][a-zA-Z0-9 _-]{0,63}$/.test(vault)) {
      throw new Error(`Invalid vault name: "${vault}". Must start with alphanumeric, may contain spaces/hyphens/underscores (max 64 chars).`);
    }
    this.vaultName = vault;
  }

  /**
   * Write a secret, replacing any previous value for the same key.
   *
   * ORDER MATTERS: create the replacement FIRST, and only delete the previous
   * item once the new one exists. The reverse order — which this used to do —
   * destroys the stored credential and then, if `op item create` fails for any
   * reason (app disconnected mid-command, vault permissions, network), leaves
   * the user with nothing. An overwrite that can lose the old value on failure
   * is not an overwrite, it is a delete with extra steps.
   *
   * Previous items are removed by ID rather than title, because between create
   * and delete two items legitimately share a title and `op item delete TITLE`
   * cannot tell them apart.
   */
  async store(key: string, value: string): Promise<void> {
    const vaultId = this.ensureVault();

    // Snapshot what is already there, BEFORE writing anything.
    const priorIds = this.findItemIdsByTitle(key, vaultId);

    // Create the new item via a JSON template file. Using a temp file (mode
    // 0600) keeps the secret value out of process argv, where it would be
    // visible in /proc/<pid>/cmdline on Linux. Always cleaned up in `finally`.
    const template = JSON.stringify({
      title: key,
      category: 'PASSWORD',
      tags: [ITEM_TAG],
      fields: [{
        id: 'password',
        type: 'CONCEALED',
        purpose: 'PASSWORD',
        value: value,
      }],
    });

    const tmpFile = path.join(os.tmpdir(), `secretless-op-${process.pid}-${Date.now()}.json`);
    try {
      fs.writeFileSync(tmpFile, template, { mode: 0o600 });
      // `--title` and `--tags` are passed as FLAGS as well as sitting in the
      // template. The template alone is not a contract we can verify offline,
      // and the tag is load-bearing: `listItems()` filters on it, so an item
      // that silently lands untagged is invisible to every later read. Flags
      // take precedence in `op item create`, so this is deterministic.
      this.op([
        'item', 'create',
        '--vault', vaultId,
        '--template', tmpFile,
        '--title', key,
        '--tags', ITEM_TAG,
      ]);
    } finally {
      try { fs.unlinkSync(tmpFile); } catch { /* already cleaned up */ }
    }

    // New value is committed. Now retire the superseded items.
    for (const id of priorIds) {
      try {
        this.op(['item', 'delete', id, '--vault', vaultId]);
      } catch {
        // The new value IS stored, so this is not a write failure. It does
        // leave a stale duplicate that would make reads ambiguous, so say so
        // rather than letting the next `get` return an old value silently.
        console.error(
          `secretless: stored "${key}" in 1Password, but could not remove the previous item (${id}).\n` +
          `  Two items now share this title and reads may return either one.\n` +
          `  Fix: op item delete ${id} --vault ${vaultId}`,
        );
      }
    }
  }

  /**
   * IDs of every item in the vault carrying this exact title.
   *
   * Deliberately does NOT filter by tag: an item written before tagging was
   * enforced, or by an older version, still shadows reads and must be cleaned
   * up. Returns empty on any failure — a snapshot we could not take must not
   * block a write.
   */
  private findItemIdsByTitle(title: string, vaultId: string): string[] {
    try {
      const out = this.op(['item', 'list', '--vault', vaultId, '--format', 'json']);
      const parsed = JSON.parse(out || '[]');
      if (!Array.isArray(parsed)) return [];
      return (parsed as OpItem[]).filter(i => i.title === title).map(i => i.id);
    } catch {
      return [];
    }
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
      this.op(['account', 'get', '--format', 'json']);
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
   * Run `op`, bounded in time.
   *
   * Without a timeout this blocks forever: `op` waits on the desktop app, and
   * the desktop app waits on a human who may not be at the machine — or on an
   * approval dialog that never rendered. A secrets lookup inside `run` then
   * hangs the user's whole command with no output at all. The window is wide
   * enough for a real Touch ID approval and short enough to fail visibly.
   */
  private op(args: string[]): string {
    try {
      return execFileSync('op', args, {
        stdio: ['pipe', 'pipe', 'pipe'],
        encoding: 'utf-8',
        timeout: opTimeoutMs(),
      }) as unknown as string;
    } catch (err) {
      const e = err as NodeJS.ErrnoException & { signal?: string };
      // execFileSync surfaces a timeout as the kill signal, but not on every
      // path — `ETIMEDOUT` appears instead depending on where it trips. Match
      // both, or a timed-out call falls through to the generic branch and
      // reports something that reads nothing like "it timed out".
      if (e?.signal === 'SIGTERM' || e?.code === 'ETIMEDOUT') {
        throw new Error(
          `1Password did not respond within ${opTimeoutMs() / 1000}s (op ${args[0]} ${args[1] ?? ''}).\n` +
          `  This usually means an approval prompt is waiting, or the desktop app is not running.\n` +
          `  Verify: op account get\n` +
          `  Fix:    open the 1Password app, unlock it, and retry\n` +
          `  Adjust: SECRETLESS_OP_TIMEOUT_MS=60000`,
        );
      }
      // Everything else: keep what `op` actually said, drop our own argv echo.
      // No secret value is ever in this argv — that is why store() writes the
      // value to a mode-0600 template file — but the echo is noise that buries
      // op's real message, and vault ids and key names do not need reprinting.
      throw new Error(
        `1Password command failed (op ${args[0]} ${args[1] ?? ''}).\n` +
        `${opStderr(e)}` +
        `  Verify: op account get`,
      );
    }
  }

  /**
   * Get or create the Secretless vault. Returns the vault ID.
   * Caches the vault ID for the lifetime of this backend instance.
   */
  private ensureVault(): string {
    const existing = this.getVaultId();
    if (existing) return existing;

    const out = this.op([
      'vault', 'create', this.vaultName,
      '--format', 'json',
    ]);

    const vault: OpVault = JSON.parse(out);
    this.cachedVaultId = vault.id;
    return vault.id;
  }

  /**
   * Look up the vault ID by name. Returns null if the vault doesn't exist
   * or the CLI is not authenticated.
   *
   * Falls back to `op vault list` when `op vault get` fails due to
   * ambiguous name (multiple vaults with the same name). This prevents
   * ensureVault() from creating duplicate vaults.
   */
  private getVaultId(): string | null {
    if (this.cachedVaultId) return this.cachedVaultId;

    // Fast path: unambiguous vault lookup
    try {
      const out = this.op([
        'vault', 'get', this.vaultName,
        '--format', 'json',
      ]);

      const vault: OpVault = JSON.parse(out);
      this.cachedVaultId = vault.id;
      return vault.id;
    } catch {
      // May fail due to: not found, ambiguous name, or auth error
    }

    // Fallback: list all vaults and find by name (handles duplicate names)
    try {
      const out = this.op([
        'vault', 'list', '--format', 'json',
      ]);

      const vaults: Array<{ id: string; name: string }> = JSON.parse(out || '[]');
      const match = vaults.find(v => v.name === this.vaultName);
      if (match) {
        this.cachedVaultId = match.id;
        return match.id;
      }
    } catch {
      // CLI not available or not authenticated
    }

    return null;
  }

  /**
   * List all secretless-tagged items in the vault.
   * Returns an empty array if the vault is empty or on error.
   */
  private listItems(vaultId: string): OpItem[] {
    try {
      const out = this.op([
        'item', 'list',
        '--vault', vaultId,
        '--tags', ITEM_TAG,
        '--format', 'json',
      ]);

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
    const out = this.op([
      'item', 'get', itemId,
      '--vault', vaultId,
      '--fields', 'password',
      '--format', 'json',
    ]);

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
    this.op([
      'item', 'delete', title,
      '--vault', vaultId,
    ]);
  }
}
