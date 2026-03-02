import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { CachedBackend, clearCacheFile } from './cache';
import type { WritableSecretBackend, BackendHealth } from './types';

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-cache-test-'));
}

function cleanup(dir: string): void {
  fs.rmSync(dir, { recursive: true, force: true });
}

function createMockBackend(secrets: Record<string, string>): WritableSecretBackend & {
  resolveCalls: number;
  storeCalls: number;
  deleteCalls: number;
} {
  const backend = {
    name: 'mock',
    resolveCalls: 0,
    storeCalls: 0,
    deleteCalls: 0,
    async store(key: string, value: string) {
      backend.storeCalls++;
      secrets[key] = value;
    },
    async resolve(prefix: string) {
      backend.resolveCalls++;
      const result: Record<string, string> = {};
      for (const [key, value] of Object.entries(secrets)) {
        if (key === prefix || key.startsWith(prefix + '/')) {
          result[key] = value;
        }
      }
      return result;
    },
    async delete(key: string) {
      backend.deleteCalls++;
      if (key in secrets) {
        delete secrets[key];
        return true;
      }
      return false;
    },
    async healthCheck(): Promise<BackendHealth> {
      return { healthy: true, latencyMs: 0, message: 'ok' };
    },
  };
  return backend;
}

describe('CachedBackend', () => {
  let dir: string;

  beforeEach(() => {
    dir = tmpDir();
  });

  afterEach(() => {
    cleanup(dir);
  });

  it('delegates to inner backend on first resolve', async () => {
    const inner = createMockBackend({ 'secret/NPM_TOKEN': 'npm_abc123' });
    const cached = new CachedBackend(inner, { ttlMs: 60_000, storeDir: dir });

    const result = await cached.resolve('secret');
    expect(result).toEqual({ 'secret/NPM_TOKEN': 'npm_abc123' });
    expect(inner.resolveCalls).toBe(1);
  });

  it('returns cached values on second resolve (no inner call)', async () => {
    const inner = createMockBackend({ 'secret/NPM_TOKEN': 'npm_abc123' });
    const cached = new CachedBackend(inner, { ttlMs: 60_000, storeDir: dir });

    await cached.resolve('secret');
    expect(inner.resolveCalls).toBe(1);

    const result = await cached.resolve('secret');
    expect(result).toEqual({ 'secret/NPM_TOKEN': 'npm_abc123' });
    expect(inner.resolveCalls).toBe(1); // Still 1 — cache hit
  });

  it('re-fetches from inner backend after TTL expires', async () => {
    const inner = createMockBackend({ 'secret/TOKEN': 'v1' });
    const cached = new CachedBackend(inner, { ttlMs: 50, storeDir: dir });

    await cached.resolve('secret');
    expect(inner.resolveCalls).toBe(1);

    // Wait for TTL to expire
    await new Promise(r => setTimeout(r, 80));

    // Force cache reload by clearing in-memory cache
    (cached as any).memCache = null;

    const result = await cached.resolve('secret');
    expect(inner.resolveCalls).toBe(2); // Cache miss — re-fetched
    expect(result).toEqual({ 'secret/TOKEN': 'v1' });
  });

  it('updates cache when store is called', async () => {
    const inner = createMockBackend({ 'secret/KEY': 'old' });
    const cached = new CachedBackend(inner, { ttlMs: 60_000, storeDir: dir });

    // Populate cache
    await cached.resolve('secret');

    // Store new value
    await cached.store('secret/KEY', 'new');
    expect(inner.storeCalls).toBe(1);

    // Resolve should hit inner because prefix marker was invalidated
    const result = await cached.resolve('secret');
    expect(result).toEqual({ 'secret/KEY': 'new' });
  });

  it('removes from cache when delete is called', async () => {
    const inner = createMockBackend({
      'secret/A': 'val_a',
      'secret/B': 'val_b',
    });
    const cached = new CachedBackend(inner, { ttlMs: 60_000, storeDir: dir });

    // Populate cache
    await cached.resolve('secret');
    expect(inner.resolveCalls).toBe(1);

    // Delete one key
    await cached.delete('secret/A');
    expect(inner.deleteCalls).toBe(1);

    // Resolve should re-fetch since prefix marker was invalidated
    const result = await cached.resolve('secret');
    expect(result).toEqual({ 'secret/B': 'val_b' });
  });

  it('passes through when TTL is 0 (disabled)', async () => {
    const inner = createMockBackend({ 'secret/KEY': 'val' });
    const cached = new CachedBackend(inner, { ttlMs: 0, storeDir: dir });

    await cached.resolve('secret');
    await cached.resolve('secret');

    // Both calls should hit the inner backend — no caching
    expect(inner.resolveCalls).toBe(2);
  });

  it('encrypts the cache file', async () => {
    const inner = createMockBackend({ 'secret/KEY': 'sensitive_value' });
    const cached = new CachedBackend(inner, { ttlMs: 60_000, storeDir: dir });

    await cached.resolve('secret');

    // Cache file should exist but not contain plaintext
    const cacheFile = path.join(dir, '.secret-cache');
    expect(fs.existsSync(cacheFile)).toBe(true);

    const raw = fs.readFileSync(cacheFile);
    expect(raw.toString('utf-8')).not.toContain('sensitive_value');
    expect(raw.toString('utf-8')).not.toContain('secret/KEY');
  });

  it('persists cache across instances', async () => {
    const secrets = { 'secret/KEY': 'persistent' };

    // First instance populates cache
    const inner1 = createMockBackend(secrets);
    const cached1 = new CachedBackend(inner1, { ttlMs: 60_000, storeDir: dir });
    await cached1.resolve('secret');
    expect(inner1.resolveCalls).toBe(1);

    // Second instance should read from file cache
    const inner2 = createMockBackend(secrets);
    const cached2 = new CachedBackend(inner2, { ttlMs: 60_000, storeDir: dir });
    const result = await cached2.resolve('secret');
    expect(result).toEqual({ 'secret/KEY': 'persistent' });
    expect(inner2.resolveCalls).toBe(0); // File cache hit
  });

  it('clearCache removes cache file and in-memory cache', async () => {
    const inner = createMockBackend({ 'secret/KEY': 'val' });
    const cached = new CachedBackend(inner, { ttlMs: 60_000, storeDir: dir });

    await cached.resolve('secret');
    expect(fs.existsSync(path.join(dir, '.secret-cache'))).toBe(true);

    cached.clearCache();
    expect(fs.existsSync(path.join(dir, '.secret-cache'))).toBe(false);

    // Next resolve should hit the inner backend
    await cached.resolve('secret');
    expect(inner.resolveCalls).toBe(2);
  });

  it('getCacheStats returns correct counts', async () => {
    const inner = createMockBackend({
      'secret/A': 'val_a',
      'secret/B': 'val_b',
    });
    const cached = new CachedBackend(inner, { ttlMs: 60_000, storeDir: dir });

    await cached.resolve('secret');
    const stats = cached.getCacheStats();
    expect(stats.entries).toBe(2);
    expect(stats.expired).toBe(0);
  });

  it('delegates healthCheck to inner backend', async () => {
    const inner = createMockBackend({});
    const cached = new CachedBackend(inner, { ttlMs: 60_000, storeDir: dir });

    const health = await cached.healthCheck();
    expect(health.healthy).toBe(true);
  });

  it('handles exact key resolve (not just prefix)', async () => {
    const inner = createMockBackend({ 'secret/EXACT': 'found' });
    const cached = new CachedBackend(inner, { ttlMs: 60_000, storeDir: dir });

    const result = await cached.resolve('secret/EXACT');
    expect(result).toEqual({ 'secret/EXACT': 'found' });

    // Second call should be cached
    const result2 = await cached.resolve('secret/EXACT');
    expect(result2).toEqual({ 'secret/EXACT': 'found' });
    expect(inner.resolveCalls).toBe(1);
  });

  it('handles empty backend gracefully', async () => {
    const inner = createMockBackend({});
    const cached = new CachedBackend(inner, { ttlMs: 60_000, storeDir: dir });

    const result = await cached.resolve('secret');
    expect(result).toEqual({});
    expect(inner.resolveCalls).toBe(1);

    // Empty results should still be cached (no re-fetch)
    const result2 = await cached.resolve('secret');
    expect(result2).toEqual({});
    expect(inner.resolveCalls).toBe(1);
  });

  it('names itself with inner backend name', () => {
    const inner = createMockBackend({});
    const cached = new CachedBackend(inner, { ttlMs: 60_000, storeDir: dir });
    expect(cached.name).toBe('cached(mock)');
  });
});

describe('clearCacheFile', () => {
  let dir: string;

  beforeEach(() => {
    dir = tmpDir();
  });

  afterEach(() => {
    cleanup(dir);
  });

  it('returns true when cache file exists and is removed', async () => {
    const inner = createMockBackend({ 'secret/K': 'v' });
    const cached = new CachedBackend(inner, { ttlMs: 60_000, storeDir: dir });
    await cached.resolve('secret');

    expect(clearCacheFile(dir)).toBe(true);
    expect(fs.existsSync(path.join(dir, '.secret-cache'))).toBe(false);
  });

  it('returns false when no cache file exists', () => {
    expect(clearCacheFile(dir)).toBe(false);
  });
});
