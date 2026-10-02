/**
 * Linux Secret Service backend — stores secrets via the `secret-tool` CLI (libsecret).
 *
 * Each secret is stored with attributes:
 *   service = "secretless"
 *   account = key (e.g. "mcp/claude-desktop/my-server/API_KEY")
 *
 * Secret values are passed via stdin (not CLI args) to avoid /proc exposure.
 *
 * A lightweight key index file tracks stored key names for prefix-based lookups.
 * The index contains only key names — never secret values.
 *
 * No shell is involved: argv is an array, and the value is on stdin only.
 * Every child call is bounded in time (see bounded-child.ts): `secret-tool`
 * blocks on the keyring unlock dialog when the collection is locked, and a
 * dialog nobody answers must not hang the user's command.
 */

import * as fs from 'fs';
import * as path from 'path';
import type { WritableSecretBackend, BackendHealth } from './types';
import { readKeyIndex } from './key-index';
import {
  BACKEND_CHILD_TIMEOUT_MS,
  runBoundedChild,
  type BoundedChildResult,
} from './bounded-child';

const LEGACY_SERVICE_NAME = 'secretless';
const INDEX_FILENAME = 'keychain-index.json';
const SECRET_TOOL_PROGRAM = 'secret-tool';

/**
 * Internal seam, for tests only. Not a config key: `createBackend` never
 * passes it, and nothing reads it from the environment or a flag.
 */
export interface LinuxKeychainInternals {
  /** Program run in place of `secret-tool`. */
  secretToolProgram?: string;
  /** Per-child bound. The default is the one named source in bounded-child.ts. */
  childTimeoutMs?: number;
}

/**
 * Derive a per-key service name so password managers show a descriptive
 * name instead of "secretless" for every entry.
 */
function serviceNameFor(key: string): string {
  const lastSegment = key.split('/').pop() ?? key;
  return `Secretless: ${lastSegment}`;
}

/**
 * The store did not land. The message carries what `secret-tool` said on
 * stderr, which holds attribute names and never the value (the value went in
 * on stdin and `secret-tool` does not echo it), and never our own argv.
 */
function secretToolStoreError(key: string, res: BoundedChildResult, timeoutMs: number): Error {
  const how = res.timedOut
    ? `secret-tool did not respond within ${timeoutMs / 1000}s and was ended.`
    : res.spawnError
      ? `secret-tool could not be started: ${res.spawnError.code ?? res.spawnError.message}`
      : `secret-tool exit status: ${typeof res.status === 'number' ? res.status : 'unknown'}`;
  const said = res.stderr.trim();
  return new Error(
    [
      `Could not store "${key}" in the Linux Secret Service.`,
      '',
      `  ${how}`,
      ...(said ? said.split('\n').map(l => `  ${l}`) : []),
      '',
      res.timedOut
        ? '  The keyring is usually locked, with an unlock dialog waiting that could'
        : '  The keyring is usually locked, or no Secret Service is running.',
      ...(res.timedOut ? ['  not be shown or was not answered.'] : []),
      '',
      '  Verify:  secret-tool search service secretless',
      '  Fix:     unlock the login keyring and retry, or run',
      '           secretless-ai backend set local  to use the encrypted file store',
    ].join('\n'),
  );
}

export class LinuxKeychainBackend implements WritableSecretBackend {
  readonly name = 'keychain-linux';
  private readonly indexPath: string;
  private readonly secretToolProgram: string;
  private readonly childTimeoutMs: number;

  constructor(config?: Record<string, unknown>, internals?: LinuxKeychainInternals) {
    const home = process.env.HOME ?? '/tmp';
    const storeDir = (config?.storeDir as string) ?? path.join(home, '.secretless-ai', 'store');
    fs.mkdirSync(storeDir, { recursive: true, mode: 0o700 });
    this.indexPath = path.join(storeDir, INDEX_FILENAME);
    // Deliberately from `internals`, never from `config`: config is user data.
    this.secretToolProgram = internals?.secretToolProgram ?? SECRET_TOOL_PROGRAM;
    this.childTimeoutMs = internals?.childTimeoutMs ?? BACKEND_CHILD_TIMEOUT_MS;
  }

  async store(key: string, value: string): Promise<void> {
    const svc = serviceNameFor(key);

    // Delete legacy entry to prevent duplicates. No legacy entry is the common
    // case, so the outcome is not inspected.
    await this.secretTool(['clear', 'service', LEGACY_SERVICE_NAME, 'account', key]);

    // secret-tool store reads the value from stdin
    const res = await this.secretTool([
      'store',
      `--label=Secretless: ${key}`,
      'service', svc,
      'account', key,
    ], value);
    if (res.spawnError || res.timedOut || res.status !== 0) {
      throw secretToolStoreError(key, res, this.childTimeoutMs);
    }

    // Update index
    const index = this.readIndex();
    if (!index.includes(key)) {
      index.push(key);
      this.writeIndex(index);
    }
  }

  async resolve(secretPath: string): Promise<Record<string, string>> {
    const index = this.readIndex();
    const matchingKeys = index.filter(
      k => k === secretPath || k.startsWith(secretPath + '/'),
    );

    const results: Record<string, string> = {};
    for (const key of matchingKeys) {
      // Try new per-key service name first, fall back to legacy
      const value = (await this.lookupSecret(serviceNameFor(key), key))
        ?? (await this.lookupSecret(LEGACY_SERVICE_NAME, key));
      if (value) {
        results[key] = value;
      }
    }
    return results;
  }

  async delete(key: string): Promise<boolean> {
    let deleted = false;

    // Delete new-format entry
    const current = await this.secretTool(['clear', 'service', serviceNameFor(key), 'account', key]);
    if (current.status === 0) deleted = true;

    // Also delete legacy entry if it exists
    const legacy = await this.secretTool(['clear', 'service', LEGACY_SERVICE_NAME, 'account', key]);
    if (legacy.status === 0) deleted = true;

    if (deleted) {
      const index = this.readIndex();
      const filtered = index.filter(k => k !== key);
      this.writeIndex(filtered);
    }

    return deleted;
  }

  async healthCheck(): Promise<BackendHealth> {
    const start = Date.now();
    const res = await runBoundedChild('which', [this.secretToolProgram], {
      timeoutMs: this.childTimeoutMs,
    });
    if (res.status === 0) {
      return {
        healthy: true,
        latencyMs: Date.now() - start,
        message: 'secret-tool available (Linux Secret Service)',
      };
    }
    return {
      healthy: false,
      latencyMs: Date.now() - start,
      message: 'secret-tool not found. Install libsecret-tools (Debian/Ubuntu) or libsecret (Fedora/RHEL).',
    };
  }

  /**
   * One place every `secret-tool` child starts: the program, the argv exactly
   * as given, the bound from its one source, and the value (when there is one)
   * on stdin.
   */
  private secretTool(args: string[], input?: string): Promise<BoundedChildResult> {
    return runBoundedChild(this.secretToolProgram, args, {
      timeoutMs: this.childTimeoutMs,
      input,
    });
  }

  /**
   * The stored value, or null. Every failure answers null here, as it did
   * before the bound was added; a timeout is one of those failures. `lookup`
   * prints the value with no trailing newline; a trailing newline that does
   * arrive is removed, as before.
   */
  private async lookupSecret(service: string, account: string): Promise<string | null> {
    const res = await this.secretTool(['lookup', 'service', service, 'account', account]);
    if (res.status !== 0) return null;
    const value = res.stdout.trimEnd();
    return value || null;
  }

  private readIndex(): string[] {
    return readKeyIndex(this.indexPath);
  }

  private writeIndex(keys: string[]): void {
    const tmpPath = this.indexPath + '.tmp';
    fs.writeFileSync(tmpPath, JSON.stringify(keys, null, 2) + '\n', { mode: 0o600 });
    fs.renameSync(tmpPath, this.indexPath);
  }
}
