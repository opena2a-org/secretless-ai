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

interface CacheEntry {
  value: string;
  cachedAt: number; // epoch ms
}

interface CacheStore {
  entries: Record<string, CacheEntry>;
}

export class CachedBackend implements WritableSecretBackend {
  readonly name: string;
  private readonly inner: WritableSecretBackend;
  private readonly cachePath: string;
  private readonly encryptionKey: Buffer;
  private readonly ttlMs: number;

  /** In-memory mirror — avoids decrypting the file on every resolve(). */
  private memCache: CacheStore | null = null;

  constructor(
    inner: WritableSecretBackend,
    options?: { ttlMs?: number; storeDir?: string },
  ) {
    this.inner = inner;
    this.name = `cached(${inner.name})`;
    this.ttlMs = options?.ttlMs ?? 5 * 60 * 1000; // default 5 minutes

    const home = process.env.HOME ?? process.env.USERPROFILE ?? '/tmp';
    const storeDir = options?.storeDir ?? path.join(home, '.secretless-ai', 'store');
    fs.mkdirSync(storeDir, { recursive: true, mode: 0o700 });
    this.cachePath = path.join(storeDir, CACHE_FILENAME);

    // Same key derivation as LocalBackend — deterministic, no extra prompt
    const keyMaterial = `${home}-secretless-cache-${process.env.USER ?? 'default'}`;
    this.encryptionKey = crypto.createHash('sha256').update(keyMaterial).digest();
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
    const prefixMarker = `__resolved__${secretPath}`;
    const markerEntry = cache.entries[prefixMarker];
    if (markerEntry && now - markerEntry.cachedAt < this.ttlMs && matchingCached.length >= 0) {
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
    for (const [key, value] of Object.entries(results)) {
      cache.entries[key] = { value, cachedAt: now };
    }
    // Mark the prefix as fully resolved
    cache.entries[prefixMarker] = { value: '', cachedAt: now };

    this.saveCache(cache);
    return results;
  }

  async store(key: string, value: string): Promise<void> {
    await this.inner.store(key, value);

    // Update cache with new value
    const cache = this.loadCache();
    cache.entries[key] = { value, cachedAt: Date.now() };
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

      // Evict expired entries on load
      const now = Date.now();
      for (const [key, entry] of Object.entries(this.memCache.entries)) {
        if (now - entry.cachedAt >= this.ttlMs) {
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
 */
export function clearCacheFile(storeDir?: string): boolean {
  const home = process.env.HOME ?? process.env.USERPROFILE ?? '/tmp';
  const dir = storeDir ?? path.join(home, '.secretless-ai', 'store');
  const cachePath = path.join(dir, CACHE_FILENAME);

  try {
    if (fs.existsSync(cachePath)) {
      fs.unlinkSync(cachePath);
      return true;
    }
    return false;
  } catch {
    return false;
  }
}
