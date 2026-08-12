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
 * Uses execFileSync (no shell) to prevent injection.
 */

import { execFileSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import type { WritableSecretBackend, BackendHealth } from './types';
import { readKeyIndex } from './key-index';

const LEGACY_SERVICE_NAME = 'secretless';
const INDEX_FILENAME = 'keychain-index.json';

/**
 * Derive a per-key service name so password managers show a descriptive
 * name instead of "secretless" for every entry.
 */
function serviceNameFor(key: string): string {
  const lastSegment = key.split('/').pop() ?? key;
  return `Secretless: ${lastSegment}`;
}

export class LinuxKeychainBackend implements WritableSecretBackend {
  readonly name = 'keychain-linux';
  private readonly indexPath: string;

  constructor(config?: Record<string, unknown>) {
    const home = process.env.HOME ?? '/tmp';
    const storeDir = (config?.storeDir as string) ?? path.join(home, '.secretless-ai', 'store');
    fs.mkdirSync(storeDir, { recursive: true, mode: 0o700 });
    this.indexPath = path.join(storeDir, INDEX_FILENAME);
  }

  async store(key: string, value: string): Promise<void> {
    const svc = serviceNameFor(key);

    // Delete legacy entry to prevent duplicates
    try {
      execFileSync('secret-tool', [
        'clear',
        'service', LEGACY_SERVICE_NAME,
        'account', key,
      ], { stdio: 'pipe' });
    } catch {
      // No legacy entry — that's fine
    }

    // secret-tool store reads the value from stdin
    execFileSync('secret-tool', [
      'store',
      `--label=Secretless: ${key}`,
      'service', svc,
      'account', key,
    ], {
      input: value,
      stdio: ['pipe', 'pipe', 'pipe'],
    });

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
      const value = this.lookupSecret(serviceNameFor(key), key)
        ?? this.lookupSecret(LEGACY_SERVICE_NAME, key);
      if (value) {
        results[key] = value;
      }
    }
    return results;
  }

  async delete(key: string): Promise<boolean> {
    let deleted = false;

    // Delete new-format entry
    try {
      execFileSync('secret-tool', [
        'clear',
        'service', serviceNameFor(key),
        'account', key,
      ], { stdio: 'pipe' });
      deleted = true;
    } catch {
      // Not found with new service name
    }

    // Also delete legacy entry if it exists
    try {
      execFileSync('secret-tool', [
        'clear',
        'service', LEGACY_SERVICE_NAME,
        'account', key,
      ], { stdio: 'pipe' });
      deleted = true;
    } catch {
      // No legacy entry
    }

    if (deleted) {
      const index = this.readIndex();
      const filtered = index.filter(k => k !== key);
      this.writeIndex(filtered);
    }

    return deleted;
  }

  async healthCheck(): Promise<BackendHealth> {
    const start = Date.now();
    try {
      execFileSync('which', ['secret-tool'], { stdio: 'pipe' });
      return {
        healthy: true,
        latencyMs: Date.now() - start,
        message: 'secret-tool available (Linux Secret Service)',
      };
    } catch {
      return {
        healthy: false,
        latencyMs: Date.now() - start,
        message: 'secret-tool not found. Install libsecret-tools (Debian/Ubuntu) or libsecret (Fedora/RHEL).',
      };
    }
  }

  private lookupSecret(service: string, account: string): string | null {
    try {
      const value = execFileSync('secret-tool', [
        'lookup',
        'service', service,
        'account', account,
      ], { stdio: ['pipe', 'pipe', 'pipe'], encoding: 'utf-8' }).trimEnd();
      return value || null;
    } catch {
      return null;
    }
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
