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

import { execFileSync, spawnSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import type { WritableSecretBackend, BackendHealth } from './types';

const LEGACY_SERVICE_NAME = 'secretless';
const INDEX_FILENAME = 'keychain-index.json';

/**
 * Derive a per-key service name so macOS Passwords.app shows a descriptive
 * name instead of "Secretless" for every entry.
 *
 * Examples:
 *   "secret/ANTHROPIC_API_KEY" → "Secretless: ANTHROPIC_API_KEY"
 *   "mcp/claude-desktop/server/TOKEN" → "Secretless: TOKEN"
 */
function serviceNameFor(key: string): string {
  const lastSegment = key.split('/').pop() ?? key;
  return `Secretless: ${lastSegment}`;
}

/**
 * macOS `security find-generic-password -w` hex-encodes passwords that contain
 * non-printable characters (e.g. newlines). Detect and decode hex output.
 *
 * **`-w` output cannot tell you which happened.** Measured:
 *
 *   stored text  "d259cc9961fbd259cc9961fbd259cc99" -> d259cc9961fbd259cc99...
 *   stored bytes  line1\nline2                      -> 6c696e65310a6c696e6532
 *
 * Identical shape. No content-based rule separates them, and the one this code
 * used to apply (decode if the decoded bytes hold a control character) silently
 * corrupted most 32-hex-character API keys. Those decode to 16 random bytes and
 * the control ranges it tested cover 32 of 256 values, so
 * `1 - (224/256)^16` = **88%** of such keys tripped it. A real HIBP key read
 * back as 16 bytes of binary. The keychain was never wrong; the read path was.
 *
 * `-g` settles it without guessing, because macOS states the encoding:
 *
 *   plain   -> password: "d259cc9961fbd259cc9961fbd259cc99"
 *   binary  -> password: 0x6C696E65310A6C696E6532  "line1\012line2"
 *
 * So: take the exact bytes from `-w`, and consult `-g` only when the shape is
 * ambiguous, which leaves the common case at one `security` call.
 *
 * Fails CLOSED on any doubt: if `-g` cannot be read, or does not clearly say
 * `0x`, the raw `-w` value is returned unchanged. Handing back a secret verbatim
 * is always safe; decoding one that was never encoded is the bug being fixed.
 */
function looksLikeKeychainHex(raw: string): boolean {
  return raw.length >= 2 && raw.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(raw);
}

export function decodeKeychainValue(
  raw: string,
  isHexEncoded?: () => boolean,
): string {
  if (!looksLikeKeychainHex(raw)) return raw;
  if (!isHexEncoded) return raw;
  // The probe shells out, so it can throw for reasons that have nothing to do
  // with this secret (keychain locked, `security` missing, spawn limit). Any of
  // those must leave the value alone rather than decode on an unanswered
  // question. Caught here as well as inside the probe: this function is
  // exported and its contract should not depend on who supplies the callback.
  let encoded = false;
  try {
    encoded = isHexEncoded();
  } catch {
    return raw;
  }
  if (!encoded) return raw;
  return Buffer.from(raw, 'hex').toString('utf-8');
}

/**
 * Parse `security find-generic-password -g` output for the explicit `0x` marker.
 *
 * Anchored to the `password:` line so a `0x` appearing inside the ATTRIBUTE dump
 * that `-g` also prints cannot be mistaken for the encoding marker.
 */
export function keychainOutputIsHexEncoded(stderrAndStdout: string): boolean {
  return /^password:\s*0x[0-9A-Fa-f]+/m.test(stderrAndStdout);
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
    const svc = serviceNameFor(key);

    // Delete existing entry (new service name)
    try {
      execFileSync('security', [
        'delete-generic-password',
        '-s', svc,
        '-a', key,
      ], { stdio: 'pipe' });
    } catch {
      // Entry didn't exist — that's fine
    }

    // Also delete legacy entry (old unified service name) to prevent duplicates
    try {
      execFileSync('security', [
        'delete-generic-password',
        '-s', LEGACY_SERVICE_NAME,
        '-a', key,
      ], { stdio: 'pipe' });
    } catch {
      // No legacy entry — that's fine
    }

    // Add the new entry with a per-key service name (visible in macOS Passwords.app)
    execFileSync('security', [
      'add-generic-password',
      '-s', svc,
      '-a', key,
      '-l', `Secretless: ${key}`,
      '-w', value,
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
      // Try new per-key service name first, fall back to legacy. Track WHICH
      // service answered: the hex-encoding question has to be asked of the same
      // entry the value came from, or the answer describes a different secret.
      let service = serviceNameFor(key);
      let raw = this.findPassword(service, key);
      if (raw === null) {
        service = LEGACY_SERVICE_NAME;
        raw = this.findPassword(service, key);
      }
      if (raw !== null) {
        const from = service;
        results[key] = decodeKeychainValue(raw, () => this.isHexEncoded(from, key));
      }
    }
    return results;
  }

  async delete(key: string): Promise<boolean> {
    let deleted = false;

    // Delete new-format entry
    try {
      execFileSync('security', [
        'delete-generic-password',
        '-s', serviceNameFor(key),
        '-a', key,
      ], { stdio: 'pipe' });
      deleted = true;
    } catch {
      // Not found with new service name
    }

    // Also delete legacy entry if it exists
    try {
      execFileSync('security', [
        'delete-generic-password',
        '-s', LEGACY_SERVICE_NAME,
        '-a', key,
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

  /**
   * Ask macOS whether it hex-encoded this entry, using the `0x` marker on the
   * `-g` password line. Only called when `-w` output is ambiguously shaped.
   *
   * `-g` prints the password line to STDERR, so both streams are captured.
   * Any failure returns false, which leaves the value undecoded.
   */
  private isHexEncoded(service: string, account: string): boolean {
    try {
      const res = spawnSync('security', [
        'find-generic-password',
        '-s', service,
        '-a', account,
        '-g',
      ], { encoding: 'utf-8' });
      if (res.error) return false;
      return keychainOutputIsHexEncoded(`${res.stderr ?? ''}\n${res.stdout ?? ''}`);
    } catch {
      return false;
    }
  }

  private findPassword(service: string, account: string): string | null {
    try {
      return execFileSync('security', [
        'find-generic-password',
        '-s', service,
        '-a', account,
        '-w',
      ], { stdio: ['pipe', 'pipe', 'pipe'], encoding: 'utf-8' }).trimEnd();
    } catch {
      return null;
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
