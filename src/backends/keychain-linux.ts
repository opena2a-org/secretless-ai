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

const SERVICE_NAME = 'secretless';
const INDEX_FILENAME = 'keychain-index.json';

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
    // secret-tool store reads the value from stdin
    execFileSync('secret-tool', [
      'store',
      '--label=secretless',
      'service', SERVICE_NAME,
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
      try {
        const value = execFileSync('secret-tool', [
          'lookup',
          'service', SERVICE_NAME,
          'account', key,
        ], { stdio: ['pipe', 'pipe', 'pipe'], encoding: 'utf-8' }).trimEnd();
        if (value) {
          results[key] = value;
        }
      } catch {
        // Key was in index but not in keyring — skip
      }
    }
    return results;
  }

  async delete(key: string): Promise<boolean> {
    try {
      execFileSync('secret-tool', [
        'clear',
        'service', SERVICE_NAME,
        'account', key,
      ], { stdio: 'pipe' });

      // Remove from index
      const index = this.readIndex();
      const filtered = index.filter(k => k !== key);
      this.writeIndex(filtered);

      return true;
    } catch {
      return false;
    }
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

  private readIndex(): string[] {
    try {
      const raw = fs.readFileSync(this.indexPath, 'utf-8');
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }

  private writeIndex(keys: string[]): void {
    const tmpPath = this.indexPath + '.tmp';
    fs.writeFileSync(tmpPath, JSON.stringify(keys, null, 2) + '\n', { mode: 0o600 });
    fs.renameSync(tmpPath, this.indexPath);
  }
}
