import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import type { WritableSecretBackend, BackendHealth } from './types';

const STORE_FILE = 'secrets.enc';
const META_FILE = 'secrets.meta.json';

interface StoreMeta {
  version: string;
  entries: Record<string, { createdAt: string }>;
}

/**
 * Local encrypted store backend — resolves secrets from a local AES-256-GCM encrypted file.
 * Used for development/local setups. Zero network dependencies.
 */
export class LocalBackend implements WritableSecretBackend {
  readonly name = 'local';
  private readonly storeDir: string;
  private readonly encryptionKey: Buffer;

  constructor(config?: Record<string, unknown>) {
    const home = process.env.HOME ?? process.env.USERPROFILE ?? '/tmp';
    this.storeDir = (config?.storeDir as string) ?? path.join(home, '.secretless-ai', 'store');

    // Derive key from machine-specific data. This deters casual reads but does not
    // protect against an attacker with filesystem access. A future version should
    // use OS keychain (macOS Keychain, libsecret) or a user-supplied passphrase.
    const keyMaterial = (config?.key as string) ?? `${home}-secretless-${process.env.USER ?? 'default'}`;
    this.encryptionKey = crypto.createHash('sha256').update(keyMaterial).digest();
  }

  async resolve(secretPath: string): Promise<Record<string, string>> {
    const storePath = path.join(this.storeDir, STORE_FILE);
    if (!fs.existsSync(storePath)) return {};

    try {
      const encrypted = fs.readFileSync(storePath);
      const decrypted = this.decrypt(encrypted);
      const store = JSON.parse(decrypted);

      // Path can be a key name or a glob pattern
      const results: Record<string, string> = {};
      for (const [key, value] of Object.entries(store)) {
        if (key === secretPath || key.startsWith(secretPath + '/')) {
          results[key] = value as string;
        }
      }
      return results;
    } catch {
      return {};
    }
  }

  async healthCheck(): Promise<BackendHealth> {
    const start = Date.now();
    const storePath = path.join(this.storeDir, STORE_FILE);
    const exists = fs.existsSync(storePath);
    return {
      healthy: exists,
      latencyMs: Date.now() - start,
      message: exists ? 'Local store available' : 'No local store found',
    };
  }

  /** Store a secret locally */
  async store(key: string, value: string): Promise<void> {
    fs.mkdirSync(this.storeDir, { recursive: true, mode: 0o700 });

    const storePath = path.join(this.storeDir, STORE_FILE);
    let store: Record<string, string> = {};

    if (fs.existsSync(storePath)) {
      try {
        const encrypted = fs.readFileSync(storePath);
        store = JSON.parse(this.decrypt(encrypted));
      } catch {
        // Corrupted store — start fresh
      }
    }

    store[key] = value;
    const encrypted = this.encrypt(JSON.stringify(store));
    fs.writeFileSync(storePath, encrypted, { mode: 0o600 });

    // Update metadata
    const metaPath = path.join(this.storeDir, META_FILE);
    let meta: StoreMeta = { version: '1', entries: {} };
    try {
      if (fs.existsSync(metaPath)) {
        meta = JSON.parse(fs.readFileSync(metaPath, 'utf-8'));
      }
    } catch { /* ignore */ }

    meta.entries[key] = { createdAt: new Date().toISOString() };
    fs.writeFileSync(metaPath, JSON.stringify(meta, null, 2), { mode: 0o600 });
  }

  /** Delete a secret by key. Returns true if the key existed, false otherwise. */
  async delete(key: string): Promise<boolean> {
    const storePath = path.join(this.storeDir, STORE_FILE);
    if (!fs.existsSync(storePath)) return false;

    let store: Record<string, string> = {};
    try {
      const encrypted = fs.readFileSync(storePath);
      store = JSON.parse(this.decrypt(encrypted));
    } catch {
      return false;
    }

    if (!(key in store)) return false;

    delete store[key];
    const encrypted = this.encrypt(JSON.stringify(store));
    fs.writeFileSync(storePath, encrypted, { mode: 0o600 });

    // Update metadata
    const metaPath = path.join(this.storeDir, META_FILE);
    try {
      if (fs.existsSync(metaPath)) {
        const meta: StoreMeta = JSON.parse(fs.readFileSync(metaPath, 'utf-8'));
        delete meta.entries[key];
        fs.writeFileSync(metaPath, JSON.stringify(meta, null, 2), { mode: 0o600 });
      }
    } catch { /* ignore */ }

    return true;
  }

  private encrypt(plaintext: string): Buffer {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.encryptionKey, iv);
    const encrypted = Buffer.concat([cipher.update(plaintext, 'utf-8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    // Format: [iv(16)][tag(16)][ciphertext]
    return Buffer.concat([iv, tag, encrypted]);
  }

  private decrypt(data: Buffer): string {
    const iv = data.subarray(0, 16);
    const tag = data.subarray(16, 32);
    const ciphertext = data.subarray(32);
    const decipher = crypto.createDecipheriv('aes-256-gcm', this.encryptionKey, iv);
    decipher.setAuthTag(tag);
    return decipher.update(ciphertext) + decipher.final('utf-8');
  }
}
