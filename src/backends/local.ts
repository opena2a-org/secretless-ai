import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import type { WritableSecretBackend, BackendHealth } from './types';

const STORE_FILE = 'secrets.enc';
const META_FILE = 'secrets.meta.json';

/**
 * Store format this build can read. Written into the metadata on every write
 * and checked on every read.
 *
 * The check has always been the point of recording a version, and it was never
 * made: `version: '1'` was stamped and never compared, so a store written in a
 * format this build does not understand would be decrypted, parsed as whatever
 * it happened to parse as, and served with exit 0 (#104). A version that is
 * never read is not a version, it is a comment.
 */
const SUPPORTED_STORE_VERSION = '1';

interface StoreMeta {
  version: string;
  entries: Record<string, { createdAt: string }>;
}

/**
 * The store exists and this build cannot read it.
 *
 * Returning "no secrets" here is the failure #104 describes: every consumer
 * downstream — `run`, `status`, `verify`, a manifest check — reads an empty
 * store as a store with nothing in it, and reports success over a credential
 * set it never saw. There is no safe guess, so there is no guess.
 */
function unreadableStoreError(storePath: string, detail: string): Error {
  return new Error(
    [
      'The local secret store could not be decrypted.',
      '',
      '  Nothing was read. Refusing to report an empty store, because an empty',
      '  store and an unreadable one are not the same thing.',
      '',
      `  Store:   ${storePath}`,
      `  Reason:  ${detail}`,
      '',
      '  The encryption key is derived from your home directory and username, so',
      '  this is usually a store written under a different account, or copied',
      '  from another machine.',
      '',
      // Not `doctor`: it reports on shell profiles and env vars and would say
      // nothing at all about this. The two inputs to the key are what a user
      // can actually check, and a changed HOME is the common cause (sudo, a
      // container, a renamed account).
      '  Verify:  printf \'%s %s\\n\' "$HOME" "$USER"   (the key derives from these)',
      '  Fix:     run under the account that wrote the store — or start a new one:',
      '           secretless-ai backend set keychain   (then re-add your secrets)',
    ].join('\n'),
  );
}

/** The store is readable but written in a format this build does not know. */
function unsupportedStoreVersionError(found: string): Error {
  return new Error(
    [
      `The local secret store is version ${found}; this build reads version ${SUPPORTED_STORE_VERSION}.`,
      '',
      '  Nothing was read. A newer store format decoded by an older build returns',
      '  bytes that are not the stored value, and every consumer downstream',
      '  believes them.',
      '',
      '  Verify:  secretless-ai --version',
      '  Fix:     npm install -g secretless-ai@latest',
    ].join('\n'),
  );
}

const SALT_FILE = '.salt';

/**
 * Load or create a 16-byte random salt for key derivation.
 * The salt is stored at `<dir>/.salt` with 0o600 permissions.
 */
function loadOrCreateSalt(dir: string): Buffer {
  const saltPath = path.join(dir, SALT_FILE);
  try {
    const existing = fs.readFileSync(saltPath);
    if (existing.length === 16) return existing;
  } catch {
    // Salt file does not exist yet — will be created below
  }
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const salt = crypto.randomBytes(16);
  fs.writeFileSync(saltPath, salt, { mode: 0o600 });
  return salt;
}

/**
 * Derive an encryption key using scrypt with a persistent random salt.
 * Falls back to SHA-256 (legacy) when no salt file exists and data was
 * encrypted with the old scheme.
 */
function deriveKey(keyMaterial: string, salt: Buffer): Buffer {
  return crypto.scryptSync(keyMaterial, salt, 32, { N: 16384, r: 8, p: 1 });
}

/**
 * Derive the legacy (pre-salt) encryption key via single SHA-256.
 * Used only during migration from the old key derivation scheme.
 */
function deriveLegacyKey(keyMaterial: string): Buffer {
  return crypto.createHash('sha256').update(keyMaterial).digest();
}

/**
 * Local encrypted store backend — resolves secrets from a local AES-256-GCM encrypted file.
 * Used for development/local setups. Zero network dependencies.
 */
export class LocalBackend implements WritableSecretBackend {
  readonly name = 'local';
  private readonly storeDir: string;
  private readonly encryptionKey: Buffer;
  private readonly keyMaterial: string;

  constructor(config?: Record<string, unknown>) {
    const home = process.env.HOME ?? process.env.USERPROFILE ?? '/tmp';
    this.storeDir = (config?.storeDir as string) ?? path.join(home, '.secretless-ai', 'store');

    // Key material is either caller-supplied or derived from machine-specific data.
    // The actual encryption key is derived via scrypt with a persistent random salt.
    this.keyMaterial = (config?.key as string) ?? `${home}-secretless-${process.env.USER ?? 'default'}`;
    const salt = loadOrCreateSalt(this.storeDir);
    this.encryptionKey = deriveKey(this.keyMaterial, salt);

    // Migration: if secrets.enc exists but was encrypted with the legacy SHA-256 key,
    // re-encrypt with the new scrypt-derived key.
    this.migrateIfNeeded();
  }

  /** Zero the encryption key buffer. Call when the backend is no longer needed. */
  destroy(): void {
    this.encryptionKey.fill(0);
  }

  /**
   * Detect and migrate data encrypted with the legacy SHA-256 key.
   * If the current (scrypt) key cannot decrypt the store but the legacy key can,
   * re-encrypt with the new key and persist.
   */
  private migrateIfNeeded(): void {
    const storePath = path.join(this.storeDir, STORE_FILE);
    if (!fs.existsSync(storePath)) return;

    try {
      // Try decrypting with the new key — if it works, no migration needed
      const data = fs.readFileSync(storePath);
      this.decrypt(data);
    } catch {
      // New key failed — try legacy key
      try {
        const data = fs.readFileSync(storePath);
        const legacyKey = deriveLegacyKey(this.keyMaterial);
        const iv = data.subarray(0, 16);
        const tag = data.subarray(16, 32);
        const ciphertext = data.subarray(32);
        const decipher = crypto.createDecipheriv('aes-256-gcm', legacyKey, iv);
        decipher.setAuthTag(tag);
        const plaintext = decipher.update(ciphertext) + decipher.final('utf-8');
        legacyKey.fill(0);

        // Legacy key worked — re-encrypt with new key
        const encrypted = this.encrypt(plaintext);
        const tmpPath = storePath + '.tmp';
        fs.writeFileSync(tmpPath, encrypted, { mode: 0o600 });
        fs.renameSync(tmpPath, storePath);
      } catch {
        // Neither key works — store is corrupted, nothing to migrate
      }
    }
  }

  /**
   * Read and decrypt the store.
   *
   * The single read path, so no caller can reach the contents by a route that
   * treats a failure differently. Absent is `{}` — a machine with no secrets yet
   * is a real, healthy state. Present-but-unreadable throws.
   */
  private readStore(): Record<string, string> {
    const storePath = path.join(this.storeDir, STORE_FILE);
    if (!fs.existsSync(storePath)) return {};

    // Version first: a store this build cannot interpret must not be decoded on
    // the chance that it parses.
    const version = this.readStoreVersion();
    if (version !== null && version !== SUPPORTED_STORE_VERSION) {
      throw unsupportedStoreVersionError(version);
    }

    // Decrypt and parse are separated so the `Reason` line can quote one and
    // never the other. A cipher error describes the ciphertext and is safe to
    // show; `JSON.parse` quotes the input it choked on, and here that input is
    // the decrypted store — so a malformed store would print secret material
    // into an error message, which is the #117 class arriving by another door.
    let plaintext: string;
    try {
      plaintext = this.decrypt(fs.readFileSync(storePath));
    } catch (err) {
      throw unreadableStoreError(storePath, err instanceof Error ? err.message : String(err));
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(plaintext);
    } catch {
      throw unreadableStoreError(storePath, 'decrypted contents are not valid JSON');
    }
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw unreadableStoreError(storePath, 'decrypted contents are not a secret map');
    }
    return parsed as Record<string, string>;
  }

  /**
   * Store format version, or null when there is no metadata to read.
   *
   * Null is not a mismatch: metadata is only written on `store()`, so a store
   * carried over from a build that never wrote it has none. Treating that as a
   * mismatch would fail closed on a store that is fine.
   */
  private readStoreVersion(): string | null {
    const metaPath = path.join(this.storeDir, META_FILE);
    if (!fs.existsSync(metaPath)) return null;
    try {
      const meta = JSON.parse(fs.readFileSync(metaPath, 'utf-8')) as Partial<StoreMeta>;
      return typeof meta.version === 'string' ? meta.version : null;
    } catch {
      // Unparseable metadata says nothing about the store's format. The store
      // itself is the thing that has to decrypt, and it is checked next.
      return null;
    }
  }

  async resolve(secretPath: string): Promise<Record<string, string>> {
    const store = this.readStore();

    // Empty prefix returns all secrets; otherwise match exact key or prefix/
    const results: Record<string, string> = {};
    for (const [key, value] of Object.entries(store)) {
      if (!secretPath || key === secretPath || key.startsWith(secretPath + '/')) {
        results[key] = value as string;
      }
    }
    return results;
  }

  async healthCheck(): Promise<BackendHealth> {
    const start = Date.now();
    const storePath = path.join(this.storeDir, STORE_FILE);
    if (!fs.existsSync(storePath)) {
      return { healthy: false, latencyMs: Date.now() - start, message: 'No local store found' };
    }
    // Presence was the whole check, so `doctor` and `verify` called a store
    // healthy on the strength of a file existing — including the store they
    // could not decrypt, which is the one case the check exists to catch.
    try {
      this.readStore();
    } catch (err) {
      return {
        healthy: false,
        latencyMs: Date.now() - start,
        message: err instanceof Error ? err.message.split('\n')[0] : 'Local store unreadable',
      };
    }
    return { healthy: true, latencyMs: Date.now() - start, message: 'Local store available' };
  }

  /** Store a secret locally */
  async store(key: string, value: string): Promise<void> {
    fs.mkdirSync(this.storeDir, { recursive: true, mode: 0o700 });

    const storePath = path.join(this.storeDir, STORE_FILE);
    // "Corrupted store — start fresh" used to sit here, swallowing the read
    // failure and writing a one-entry store over the top. Storing one secret
    // silently deleted every other one, and the command printed "Stored: NAME"
    // and exited 0. A write is the worst possible moment to guess.
    const store: Record<string, string> = this.readStore();

    store[key] = value;
    const encrypted = this.encrypt(JSON.stringify(store));
    const tmpStorePath = storePath + '.tmp';
    fs.writeFileSync(tmpStorePath, encrypted, { mode: 0o600 });
    fs.renameSync(tmpStorePath, storePath);

    // Update metadata
    const metaPath = path.join(this.storeDir, META_FILE);
    let meta: StoreMeta = { version: SUPPORTED_STORE_VERSION, entries: {} };
    try {
      if (fs.existsSync(metaPath)) {
        meta = JSON.parse(fs.readFileSync(metaPath, 'utf-8'));
      }
    } catch { /* ignore */ }

    // This build just wrote the store, so this build's format is what it is in.
    // Carrying forward whatever the file said would let an unstamped store stay
    // unstamped forever, and the version check has nothing to read.
    meta.version = SUPPORTED_STORE_VERSION;
    meta.entries = meta.entries ?? {};
    meta.entries[key] = { createdAt: new Date().toISOString() };
    const tmpMetaPath = metaPath + '.tmp';
    fs.writeFileSync(tmpMetaPath, JSON.stringify(meta, null, 2), { mode: 0o600 });
    fs.renameSync(tmpMetaPath, metaPath);
  }

  /** Delete a secret by key. Returns true if the key existed, false otherwise. */
  async delete(key: string): Promise<boolean> {
    const storePath = path.join(this.storeDir, STORE_FILE);
    if (!fs.existsSync(storePath)) return false;

    // `false` here means "there was no such secret", and an unreadable store
    // cannot support that claim. `secret rm` reported the entry gone while it
    // sat in the store untouched.
    const store: Record<string, string> = this.readStore();

    if (!(key in store)) return false;

    delete store[key];
    const encrypted = this.encrypt(JSON.stringify(store));
    const tmpStorePath = storePath + '.tmp';
    fs.writeFileSync(tmpStorePath, encrypted, { mode: 0o600 });
    fs.renameSync(tmpStorePath, storePath);

    // Update metadata
    const metaPath = path.join(this.storeDir, META_FILE);
    try {
      if (fs.existsSync(metaPath)) {
        const meta: StoreMeta = JSON.parse(fs.readFileSync(metaPath, 'utf-8'));
        delete meta.entries[key];
        const tmpMetaPath = metaPath + '.tmp';
        fs.writeFileSync(tmpMetaPath, JSON.stringify(meta, null, 2), { mode: 0o600 });
        fs.renameSync(tmpMetaPath, metaPath);
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
