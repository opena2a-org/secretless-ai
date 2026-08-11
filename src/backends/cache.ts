/**
 * Caching wrapper for secret backends that trigger OS authentication prompts.
 *
 * Wraps a WritableSecretBackend and caches resolved values in an AES-256-GCM
 * encrypted file. On resolve(), checks the cache first and only delegates to the
 * underlying backend when the cache misses or the TTL expires.
 *
 * This eliminates repeated macOS fingerprint / Linux password prompts when
 * multiple tools (npm, git, etc.) read secrets in quick succession.
 *
 * Cache file: ~/.secretless-ai/store/.secret-cache
 * Format: AES-256-GCM encrypted JSON with per-entry timestamps.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import type { WritableSecretBackend, BackendHealth } from './types';

const CACHE_FILENAME = '.secret-cache';
const SALT_FILE = '.salt';

interface CacheEntry {
  value: string;
  cachedAt: number; // epoch ms
  /** Writer stamp — see WRITER_STAMP. Absent on entries written before 0.21.4. */
  writer?: string;
  /**
   * On a prefix marker only: how many entries the resolve that wrote this marker
   * actually cached. The marker claims "this prefix is fully resolved"; without
   * the count it cannot tell a complete cache from one whose entries are gone.
   */
  count?: number;
}

interface CacheStore {
  entries: Record<string, CacheEntry>;
}

/**
 * Identity of the build that wrote a cache entry. A cached value is only served
 * back to the same build that produced it.
 *
 * A TTL bounds how STALE a value may be; it says nothing about how it was READ.
 * #107 fixed a read path that corrupted most 32-hex secrets, and the fix changed
 * no file format at all — so a format-version constant would not have been
 * bumped, and the corrupted value would still have been served. The build
 * boundary is the one place a value's provenance actually changes, which makes
 * it the thing to record (#118).
 *
 * Version alone is not the build: a working tree, a global install and an `npx`
 * unpack can all report the same version while running different code, and the
 * working tree is where a read path is most likely to be mid-fix. The install
 * root is folded in (hashed, so no path is written into the file) to separate
 * them. The cost of that precision is at most one extra unlock prompt when a
 * user alternates between two installs of the same version; the cost of missing
 * it is serving a credential read by code we already know was wrong.
 */
const WRITER_STAMP: string = computeWriterStamp();

function computeWriterStamp(): string {
  let version = 'unknown';
  try {
    version = String((require('../../package.json') as { version: string }).version);
  } catch {
    // Version is unreadable only in an unpacked-wrong install; an "unknown"
    // stamp is stable within that install and still separates it from a real
    // one, which is the property that matters.
  }
  const root = path.resolve(__dirname, '..', '..');
  const rootHash = crypto.createHash('sha256').update(root).digest('hex').slice(0, 8);
  return `${version}+${rootHash}`;
}

/**
 * The stamp production actually uses. Exported so a test can assert the default
 * is derived from the real package version rather than from whatever a test
 * injected — an injected stamp proves the comparison works, not that the thing
 * being compared is real.
 */
export function defaultWriterStamp(): string {
  return WRITER_STAMP;
}

/** Default cache directory. Shared so `clearCacheFile` cannot drift off it. */
function defaultCacheDir(): string {
  const home = process.env.HOME ?? process.env.USERPROFILE ?? '/tmp';
  return path.join(home, '.secretless-ai', 'cache');
}

/**
 * Where the cache lived until 0.12.3, alongside the store itself. Still cleared,
 * because a machine that ran an older build is carrying an encrypted file full
 * of credential values that nothing reads and nothing expires.
 */
function legacyCacheDir(): string {
  const home = process.env.HOME ?? process.env.USERPROFILE ?? '/tmp';
  return path.join(home, '.secretless-ai', 'store');
}

/**
 * Load or create a 16-byte random salt for key derivation.
 * The salt is stored at `<dir>/.salt` with 0o600 permissions.
 */
function loadOrCreateCacheSalt(dir: string): Buffer {
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

export class CachedBackend implements WritableSecretBackend {
  readonly name: string;
  private readonly inner: WritableSecretBackend;
  private readonly cachePath: string;
  private readonly cacheDir: string;
  private readonly encryptionKey: Buffer;
  private readonly ttlMs: number;
  /**
   * Overridable ONLY so a test can play two builds against one cache file.
   * Production never passes it — `defaultWriterStamp` pins the default to the
   * real package version, so an injected stamp cannot make a broken default
   * look correct.
   */
  private readonly writerStamp: string;

  /** In-memory mirror — avoids decrypting the file on every resolve(). */
  private memCache: CacheStore | null = null;

  constructor(
    inner: WritableSecretBackend,
    options?: { ttlMs?: number; storeDir?: string; writerStamp?: string },
  ) {
    this.inner = inner;
    this.name = `cached(${inner.name})`;
    this.ttlMs = options?.ttlMs ?? 5 * 60 * 1000; // default 5 minutes
    this.writerStamp = options?.writerStamp ?? WRITER_STAMP;

    const home = process.env.HOME ?? process.env.USERPROFILE ?? '/tmp';
    const storeDir = options?.storeDir ?? defaultCacheDir();
    fs.mkdirSync(storeDir, { recursive: true, mode: 0o700 });
    this.cacheDir = storeDir;
    this.cachePath = path.join(storeDir, CACHE_FILENAME);

    // Derive key via scrypt with a persistent random salt
    const keyMaterial = `${home}-secretless-cache-${process.env.USER ?? 'default'}`;
    const salt = loadOrCreateCacheSalt(storeDir);
    this.encryptionKey = crypto.scryptSync(keyMaterial, salt, 32, { N: 16384, r: 8, p: 1 });

    this.discardUnreadableCache();
  }

  /** Zero the encryption key buffer. Call when the backend is no longer needed. */
  destroy(): void {
    this.encryptionKey.fill(0);
  }

  /**
   * Drop a cache file this build cannot read.
   *
   * This used to re-encrypt a cache written under the pre-scrypt SHA-256 key so
   * its entries survived the key change. That migration is now unreachable by
   * construction: every entry it recovered was written by an older build, and
   * `loadCache` drops entries whose writer stamp is not ours — so the recovered
   * plaintext could never be served. What it did do was keep a second decryption
   * path over live credential values alive for no observable gain. A cache is
   * disposable; the whole cost of discarding one is a single unlock prompt.
   */
  private discardUnreadableCache(): void {
    if (!fs.existsSync(this.cachePath)) return;
    try {
      this.decrypt(fs.readFileSync(this.cachePath));
    } catch {
      try { fs.unlinkSync(this.cachePath); } catch { /* ignore */ }
    }
  }

  async resolve(secretPath: string): Promise<Record<string, string>> {
    if (this.ttlMs <= 0) {
      // Cache disabled — pass through
      return this.inner.resolve(secretPath);
    }

    const cache = this.loadCache();
    const now = Date.now();

    // Check if ALL matching keys in the cache are still valid.
    // We use a simple strategy: look for keys that match the prefix.
    const cachedResults: Record<string, string> = {};
    let allCached = false;

    // We need the index to know which keys match the prefix.
    // The cache stores full keys, so we can filter by prefix.
    const matchingCached: [string, CacheEntry][] = [];
    for (const [key, entry] of Object.entries(cache.entries)) {
      if (key === secretPath || key.startsWith(secretPath + '/')) {
        if (now - entry.cachedAt < this.ttlMs) {
          matchingCached.push([key, entry]);
        }
      }
    }

    // If we have a cache marker indicating this prefix was fully resolved,
    // we can trust the cached entries. The marker is the prefix itself.
    //
    // The marker's claim is completeness, so it has to carry the count it was
    // written with. The old condition here was `matchingCached.length >= 0` —
    // true for every possible value — so a surviving marker over missing entries
    // reported "fully resolved" and returned {}. That is the worst shape this
    // class has: `run` would inject NOTHING and still exit 0. Any shortfall is
    // now a miss.
    const prefixMarker = `__resolved__${secretPath}`;
    const markerEntry = cache.entries[prefixMarker];
    if (
      markerEntry &&
      now - markerEntry.cachedAt < this.ttlMs &&
      matchingCached.length === (markerEntry.count ?? -1)
    ) {
      allCached = true;
      for (const [key, entry] of matchingCached) {
        cachedResults[key] = entry.value;
      }
    }

    if (allCached) {
      return cachedResults;
    }

    // Cache miss or expired — resolve from the real backend
    const results = await this.inner.resolve(secretPath);

    // Store results in cache
    let cachedCount = 0;
    for (const [key, value] of Object.entries(results)) {
      cache.entries[key] = { value, cachedAt: now, writer: this.writerStamp };
      cachedCount++;
    }
    // Mark the prefix as fully resolved
    cache.entries[prefixMarker] = {
      value: '',
      cachedAt: now,
      writer: this.writerStamp,
      count: cachedCount,
    };

    this.saveCache(cache);
    return results;
  }

  async store(key: string, value: string): Promise<void> {
    await this.inner.store(key, value);

    // Update cache with new value
    const cache = this.loadCache();
    cache.entries[key] = { value, cachedAt: Date.now(), writer: this.writerStamp };
    // Invalidate prefix markers that cover this key
    this.invalidatePrefixMarkers(cache, key);
    this.saveCache(cache);
  }

  async delete(key: string): Promise<boolean> {
    const result = await this.inner.delete(key);

    // Remove from cache
    const cache = this.loadCache();
    delete cache.entries[key];
    this.invalidatePrefixMarkers(cache, key);
    this.saveCache(cache);

    return result;
  }

  async healthCheck(): Promise<BackendHealth> {
    return this.inner.healthCheck();
  }

  /** Clear the entire cache. */
  clearCache(): void {
    this.memCache = { entries: {} };
    try {
      if (fs.existsSync(this.cachePath)) {
        fs.unlinkSync(this.cachePath);
      }
    } catch {
      // Ignore — file may not exist
    }
  }

  /** Get the number of valid (non-expired) entries in the cache. */
  getCacheStats(): { entries: number; expired: number } {
    const cache = this.loadCache();
    const now = Date.now();
    let valid = 0;
    let expired = 0;
    for (const [key, entry] of Object.entries(cache.entries)) {
      if (key.startsWith('__resolved__')) continue;
      if (now - entry.cachedAt < this.ttlMs) {
        valid++;
      } else {
        expired++;
      }
    }
    return { entries: valid, expired };
  }

  private invalidatePrefixMarkers(cache: CacheStore, key: string): void {
    // Invalidate any prefix marker that covers this key
    // e.g. if key is "secret/NPM_TOKEN", invalidate "__resolved__secret"
    const parts = key.split('/');
    for (let i = 0; i < parts.length; i++) {
      const prefix = parts.slice(0, i + 1).join('/');
      delete cache.entries[`__resolved__${prefix}`];
    }
  }

  private loadCache(): CacheStore {
    if (this.memCache) return this.memCache;

    try {
      if (!fs.existsSync(this.cachePath)) {
        this.memCache = { entries: {} };
        return this.memCache;
      }

      const encrypted = fs.readFileSync(this.cachePath);
      const decrypted = this.decrypt(encrypted);
      this.memCache = JSON.parse(decrypted) as CacheStore;

      // Evict on load: too old, or not written by this build.
      //
      // Both checks live here, at the single point every read and write goes
      // through, so no caller can consult a stale entry by taking a different
      // route. Markers are entries too and are dropped by the same rule — a
      // marker that outlived its entries is the fail-open described in
      // resolve().
      const now = Date.now();
      for (const [key, entry] of Object.entries(this.memCache.entries)) {
        if (now - entry.cachedAt >= this.ttlMs || entry.writer !== this.writerStamp) {
          delete this.memCache.entries[key];
        }
      }

      return this.memCache;
    } catch {
      this.memCache = { entries: {} };
      return this.memCache;
    }
  }

  private saveCache(cache: CacheStore): void {
    this.memCache = cache;
    try {
      const plaintext = JSON.stringify(cache);
      const encrypted = this.encrypt(plaintext);
      const tmpPath = this.cachePath + '.tmp';
      fs.writeFileSync(tmpPath, encrypted, { mode: 0o600 });
      fs.renameSync(tmpPath, this.cachePath);
    } catch {
      // Non-fatal — cache is best-effort
    }
  }

  private encrypt(plaintext: string): Buffer {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.encryptionKey, iv);
    const encrypted = Buffer.concat([cipher.update(plaintext, 'utf-8'), cipher.final()]);
    const tag = cipher.getAuthTag();
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

/**
 * Clear the secret cache file without needing a backend instance.
 * Used by the CLI `cache clear` command.
 *
 * The default directory has to be the one `CachedBackend` actually writes to.
 * It was not: the cache moved to `cache/` in 0.12.3 and this function was left
 * pointing at `store/`, so from 0.12.3 to 0.21.3 `cache clear` deleted the
 * abandoned pre-0.12.3 file, printed "Cache cleared", and left every live entry
 * in place. #118 names `cache clear` as the remedy for a stale cached
 * credential, which made the one documented workaround a no-op that reported
 * success. Both paths are cleared now, and both share `CachedBackend`'s own
 * default so they cannot drift apart again.
 */
export function clearCacheFile(storeDir?: string): boolean {
  const dirs = storeDir ? [storeDir] : [defaultCacheDir(), legacyCacheDir()];

  let removed = false;
  for (const dir of dirs) {
    const cachePath = path.join(dir, CACHE_FILENAME);
    try {
      if (fs.existsSync(cachePath)) {
        fs.unlinkSync(cachePath);
        removed = true;
      }
    } catch {
      // Best effort per path — an unreadable directory must not stop the others.
    }
  }
  return removed;
}
