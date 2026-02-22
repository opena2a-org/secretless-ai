/**
 * macOS Keychain backend — stores secrets in the system Keychain using the `security` CLI.
 *
 * Each secret is stored as a generic password with:
 *   service = "secretless"
 *   account = key (e.g. "mcp/claude-desktop/my-server/API_KEY")
 *
 * A lightweight key index file tracks stored key names for prefix-based lookups.
 * The index contains only key names — never secret values.
 *
 * Uses execFileSync (no shell) to prevent injection via secret values.
 */

import { execFileSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import type { WritableSecretBackend, BackendHealth } from './types';

const SERVICE_NAME = 'secretless';
const INDEX_FILENAME = 'keychain-index.json';

/**
 * macOS `security find-generic-password -w` hex-encodes passwords that contain
 * non-printable characters (e.g. newlines). Detect and decode hex output.
 *
 * Hex output: even-length string matching /^[0-9a-fA-F]+$/.
 * To avoid false positives on normal hex-like passwords (e.g. "deadbeef"),
 * only decode if the hex bytes contain at least one non-printable character.
 */
function decodeKeychainValue(raw: string): string {
  if (raw.length >= 2 && raw.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(raw)) {
    const buf = Buffer.from(raw, 'hex');
    const decoded = buf.toString('utf-8');
    // Only use decoded value if it contains a non-printable char (newline, tab, etc.)
    // This prevents false-positive decoding of passwords that happen to look like hex
    if (/[\x00-\x08\x0a-\x1f\x7f]/.test(decoded)) {
      return decoded;
    }
  }
  return raw;
}

export class MacOSKeychainBackend implements WritableSecretBackend {
  readonly name = 'keychain-macos';
  private readonly indexPath: string;

  constructor(config?: Record<string, unknown>) {
    const home = process.env.HOME ?? process.env.USERPROFILE ?? '/tmp';
    const storeDir = (config?.storeDir as string) ?? path.join(home, '.secretless-ai', 'store');
    fs.mkdirSync(storeDir, { recursive: true, mode: 0o700 });
    this.indexPath = path.join(storeDir, INDEX_FILENAME);
  }

  async store(key: string, value: string): Promise<void> {
    // Delete existing entry first (ignore errors if it doesn't exist)
    try {
      execFileSync('security', [
        'delete-generic-password',
        '-s', SERVICE_NAME,
        '-a', key,
      ], { stdio: 'pipe' });
    } catch {
      // Entry didn't exist — that's fine
    }

    // Add the new entry
    execFileSync('security', [
      'add-generic-password',
      '-s', SERVICE_NAME,
      '-a', key,
      '-w', value,
      '-U',
    ], { stdio: 'pipe' });

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
        const raw = execFileSync('security', [
          'find-generic-password',
          '-s', SERVICE_NAME,
          '-a', key,
          '-w',
        ], { stdio: ['pipe', 'pipe', 'pipe'], encoding: 'utf-8' }).trimEnd();
        results[key] = decodeKeychainValue(raw);
      } catch {
        // Key was in index but not in keychain — skip (stale index entry)
      }
    }
    return results;
  }

  async delete(key: string): Promise<boolean> {
    try {
      execFileSync('security', [
        'delete-generic-password',
        '-s', SERVICE_NAME,
        '-a', key,
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
      execFileSync('security', ['default-keychain'], { stdio: 'pipe' });
      return {
        healthy: true,
        latencyMs: Date.now() - start,
        message: 'macOS Keychain available',
      };
    } catch {
      return {
        healthy: false,
        latencyMs: Date.now() - start,
        message: 'macOS Keychain not accessible',
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
