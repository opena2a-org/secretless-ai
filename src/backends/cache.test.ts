import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import { CachedBackend, clearCacheFile, defaultWriterStamp } from './cache';
import type { WritableSecretBackend, BackendHealth } from './types';

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-cache-test-'));
}

/**
 * Write a cache file by hand, in the on-disk format, so a test can stage a
 * cache state that no single run of the current code produces — an entry from
 * before writer stamps existed, or a marker that outlived its entries.
 *
 * This mirrors the implementation's key derivation deliberately: it is building
 * an INPUT, not computing an expected output. If the derivation ever changes,
 * these tests fail loudly rather than quietly staging a file nothing reads.
 */
function writeCacheFile(dir: string, store: unknown): void {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const saltPath = path.join(dir, '.salt');
  let salt: Buffer;
  try {
    salt = fs.readFileSync(saltPath);
    if (salt.length !== 16) throw new Error('bad salt');
  } catch {
    salt = crypto.randomBytes(16);
    fs.writeFileSync(saltPath, salt, { mode: 0o600 });
  }

  const home = process.env.HOME ?? process.env.USERPROFILE ?? '/tmp';
  const keyMaterial = `${home}-secretless-cache-${process.env.USER ?? 'default'}`;
  const key = crypto.scryptSync(keyMaterial, salt, 32, { N: 16384, r: 8, p: 1 });

  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const body = Buffer.concat([
    cipher.update(JSON.stringify(store), 'utf-8'),
    cipher.final(),
  ]);
  fs.writeFileSync(
    path.join(dir, '.secret-cache'),
    Buffer.concat([iv, cipher.getAuthTag(), body]),
    { mode: 0o600 },
  );
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

  // #375: the wrapped backend decides what an exact read does, so it has to
  // be told. A cache miss and a disabled cache are the two places it is asked.
  it.each([
    ['on a cache miss', 60_000],
    ['with the cache disabled', 0],
  ])('passes the resolve options to the inner backend %s', async (_when, ttlMs) => {
    const inner = createMockBackend({});
    const resolve = vi.spyOn(inner, 'resolve');
    const cached = new CachedBackend(inner, { ttlMs, storeDir: dir });

    await cached.resolve('secret/MISSING_NAME', { exact: true });

    expect(resolve.mock.calls).toEqual([['secret/MISSING_NAME', { exact: true }]]);
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

/**
 * #118 — a cached value written by a different build is a value read by code we
 * may already have fixed. The TTL bounds staleness in time; nothing bounded it
 * across an upgrade, so upgrading to fix a corrupted credential returned the
 * corrupted credential for another five minutes.
 */
describe('CachedBackend writer provenance (#118)', () => {
  let dir: string;

  beforeEach(() => {
    dir = tmpDir();
  });

  afterEach(() => {
    cleanup(dir);
  });

  it('does not serve an entry written by a different build', async () => {
    const secrets = { 'secret/HIBP_PRO': 'corrupted-by-the-old-read-path' };

    // The build with the broken read path caches what it read.
    const before = new CachedBackend(createMockBackend(secrets), {
      ttlMs: 60_000,
      storeDir: dir,
      writerStamp: '0.18.2+aaaaaaaa',
    });
    expect(await before.resolve('secret')).toEqual({
      'secret/HIBP_PRO': 'corrupted-by-the-old-read-path',
    });

    // The user upgrades. The backend now reads the value correctly — which is
    // the entire reason they upgraded.
    secrets['secret/HIBP_PRO'] = '0123456789abcdef0123456789abcdef';
    const inner = createMockBackend(secrets);
    const after = new CachedBackend(inner, {
      ttlMs: 60_000,
      storeDir: dir,
      writerStamp: '0.21.4+bbbbbbbb',
    });

    expect(await after.resolve('secret')).toEqual({
      'secret/HIBP_PRO': '0123456789abcdef0123456789abcdef',
    });
    expect(inner.resolveCalls).toBe(1);
  });

  it('still serves an entry written by this same build', async () => {
    // The other direction. Without it, a "fix" that simply never reads the
    // cache would pass the test above while deleting the feature.
    const secrets = { 'secret/K': 'v1' };
    const inner = createMockBackend(secrets);
    const opts = { ttlMs: 60_000, storeDir: dir, writerStamp: '0.21.4+bbbbbbbb' };

    await new CachedBackend(inner, opts).resolve('secret');
    expect(inner.resolveCalls).toBe(1);

    secrets['secret/K'] = 'v2-not-yet-visible';
    const second = new CachedBackend(inner, opts);
    expect(await second.resolve('secret')).toEqual({ 'secret/K': 'v1' });
    expect(inner.resolveCalls).toBe(1);
  });

  it('treats an entry with no writer stamp as a miss', async () => {
    // Every entry on disk today is one of these. The upgrade that introduces
    // the stamp has to invalidate what the previous build left behind, or the
    // fix does not take effect until the caches happen to expire.
    const legacyCache = {
      entries: {
        'secret/K': { value: 'written-before-stamps-existed', cachedAt: Date.now() },
        '__resolved__secret': { value: '', cachedAt: Date.now() },
      },
    };
    writeCacheFile(dir, legacyCache);

    const inner = createMockBackend({ 'secret/K': 'current' });
    const cached = new CachedBackend(inner, { ttlMs: 60_000, storeDir: dir });

    expect(await cached.resolve('secret')).toEqual({ 'secret/K': 'current' });
    expect(inner.resolveCalls).toBe(1);
  });

  it('pins the default stamp to the real package version', () => {
    // The tests above inject a stamp. That proves the comparison works, not
    // that the value being compared is the build. This is the wire to reality:
    // production passes no stamp, so the default is what actually ships.
    const pkgVersion = String(
      (JSON.parse(
        fs.readFileSync(path.join(__dirname, '..', '..', 'package.json'), 'utf-8'),
      ) as { version: string }).version,
    );
    expect(defaultWriterStamp().startsWith(pkgVersion + '+')).toBe(true);
    expect(defaultWriterStamp()).not.toBe(pkgVersion);
  });

  it('treats a resolved-marker with missing entries as a miss, not an empty success', async () => {
    // The marker asserts "this prefix is fully resolved". The condition guarding
    // it was `matchingCached.length >= 0`, true for every possible value, so a
    // marker that outlived its entries reported success and returned {} —
    // `run` would inject nothing and exit 0.
    const stamp = '0.21.4+bbbbbbbb';
    writeCacheFile(dir, {
      entries: {
        '__resolved__secret': { value: '', cachedAt: Date.now(), writer: stamp, count: 2 },
      },
    });

    const inner = createMockBackend({ 'secret/A': 'a', 'secret/B': 'b' });
    const cached = new CachedBackend(inner, { ttlMs: 60_000, storeDir: dir, writerStamp: stamp });

    expect(await cached.resolve('secret')).toEqual({ 'secret/A': 'a', 'secret/B': 'b' });
    expect(inner.resolveCalls).toBe(1);
  });
});

/**
 * #118 — `cache clear` is the workaround the issue documents for a stale cached
 * credential. It cleared a directory the cache stopped using in 0.12.3.
 */
describe('clearCacheFile default location', () => {
  let home: string;
  let originalHome: string | undefined;

  beforeEach(() => {
    home = tmpDir();
    originalHome = process.env.HOME;
    process.env.HOME = home;
  });

  afterEach(() => {
    if (originalHome === undefined) delete process.env.HOME;
    else process.env.HOME = originalHome;
    cleanup(home);
  });

  it('clears the cache the backend actually writes', async () => {
    const secrets = { 'secret/K': 'stale' };
    // No storeDir — this is the production path, the one that has to match.
    const first = new CachedBackend(createMockBackend(secrets), { ttlMs: 60_000 });
    await first.resolve('secret');

    expect(clearCacheFile()).toBe(true);

    secrets['secret/K'] = 'fresh';
    const inner = createMockBackend(secrets);
    const second = new CachedBackend(inner, { ttlMs: 60_000 });
    expect(await second.resolve('secret')).toEqual({ 'secret/K': 'fresh' });
    expect(inner.resolveCalls).toBe(1);
  });

  it('also clears the pre-0.12.3 cache left beside the store', () => {
    const legacyDir = path.join(home, '.secretless-ai', 'store');
    fs.mkdirSync(legacyDir, { recursive: true, mode: 0o700 });
    const legacyFile = path.join(legacyDir, '.secret-cache');
    fs.writeFileSync(legacyFile, Buffer.from('abandoned encrypted credential cache'));

    expect(clearCacheFile()).toBe(true);
    expect(fs.existsSync(legacyFile)).toBe(false);
  });
});

/**
 * Every entry and every prefix marker is kept under the scope of the backend
 * that read or wrote it: the store it came from and the credential it was
 * read with. A read is served only from its own scope. The scope is passed
 * here as the factory passes it (factory.test.ts builds it from real
 * backends).
 */
describe('CachedBackend store scope', () => {
  const SCOPE_A = 'scope-of-store-a';
  const SCOPE_B = 'scope-of-store-b';
  let dir: string;

  beforeEach(() => {
    dir = tmpDir();
  });

  afterEach(() => {
    cleanup(dir);
  });

  function inScope(inner: WritableSecretBackend, scope: string, writerStamp?: string): CachedBackend {
    return new CachedBackend(inner, { ttlMs: 60_000, storeDir: dir, scope, writerStamp });
  }

  it('(c) a value stored in one scope is a miss for an exact read in another', async () => {
    await inScope(createMockBackend({}), SCOPE_A).store('secret/X', 'stored-in-a');

    const innerB = createMockBackend({ 'secret/X': 'held-by-b' });
    expect(await inScope(innerB, SCOPE_B).resolve('secret/X', { exact: true })).toEqual({
      'secret/X': 'held-by-b',
    });
    expect(innerB.resolveCalls).toBe(1);
  });

  it('(d) a prefix read in one scope is a miss for an exact read of a child, and for a prefix read, in another', async () => {
    await inScope(createMockBackend({ 'secret/X': 'held-by-a' }), SCOPE_A).resolve('secret');

    const innerB = createMockBackend({ 'secret/X': 'held-by-b' });
    const readerB = inScope(innerB, SCOPE_B);
    expect(await readerB.resolve('secret/X', { exact: true })).toEqual({ 'secret/X': 'held-by-b' });
    expect(innerB.resolveCalls).toBe(1);

    expect(await inScope(innerB, SCOPE_B).resolve('secret')).toEqual({ 'secret/X': 'held-by-b' });
    expect(innerB.resolveCalls).toBe(2);
  });

  it('(e) CONTROL: within one scope, what an exact read, a prefix read and a store cached is served with no backend call', async () => {
    const secrets = { 'secret/X': 'held-x', 'secret/Y': 'held-y' };
    await inScope(createMockBackend(secrets), SCOPE_A).resolve('secret/X', { exact: true });
    await inScope(createMockBackend(secrets), SCOPE_A).resolve('secret');

    const prefixReader = createMockBackend(secrets);
    expect(await inScope(prefixReader, SCOPE_A).resolve('secret')).toEqual({
      'secret/X': 'held-x',
      'secret/Y': 'held-y',
    });
    expect(prefixReader.resolveCalls).toBe(0);

    await inScope(createMockBackend(secrets), SCOPE_A).store('secret/Z', 'stored-z');

    const inner = createMockBackend(secrets);
    const reader = inScope(inner, SCOPE_A);
    expect(await reader.resolve('secret/X', { exact: true })).toEqual({ 'secret/X': 'held-x' });
    expect(await reader.resolve('secret/Y', { exact: true })).toEqual({ 'secret/Y': 'held-y' });
    expect(await reader.resolve('secret/Z', { exact: true })).toEqual({ 'secret/Z': 'stored-z' });
    expect(inner.resolveCalls).toBe(0);
  });

  it('(g) an entry and a marker written without a scope are a miss', async () => {
    // The shape a build that kept no scope wrote, under this build's stamp, so
    // the writer check alone does not drop it.
    const stamp = '0.23.1+cccccccc';
    writeCacheFile(dir, {
      entries: {
        'secret/X': { value: 'cached-without-a-scope', cachedAt: Date.now(), writer: stamp },
        '__resolved__secret': { value: '', cachedAt: Date.now(), writer: stamp, count: 1 },
      },
    });

    const inner = createMockBackend({ 'secret/X': 'held' });
    const cached = inScope(inner, SCOPE_A, stamp);
    expect(await cached.resolve('secret/X', { exact: true })).toEqual({ 'secret/X': 'held' });
    expect(inner.resolveCalls).toBe(1);
    expect(await cached.resolve('secret')).toEqual({ 'secret/X': 'held' });
    expect(inner.resolveCalls).toBe(2);
  });

  it('a store or a delete in one scope clears the name in every scope, so none serves a value its store may no longer hold', async () => {
    const innerA = createMockBackend({ 'secret/X': 'held-by-a' });
    await inScope(innerA, SCOPE_A).resolve('secret/X', { exact: true });
    await inScope(createMockBackend({}), SCOPE_B).store('secret/X', 'stored-in-b');
    await inScope(innerA, SCOPE_A).resolve('secret/X', { exact: true });
    expect(innerA.resolveCalls).toBe(2);

    await inScope(createMockBackend({}), SCOPE_B).delete('secret/X');
    await inScope(innerA, SCOPE_A).resolve('secret/X', { exact: true });
    expect(innerA.resolveCalls).toBe(3);
  });

  it('keeps the value each scope read under one name, so two scopes do not displace each other', async () => {
    await inScope(createMockBackend({ 'secret/X': 'held-by-a' }), SCOPE_A).resolve('secret/X', { exact: true });
    await inScope(createMockBackend({ 'secret/X': 'held-by-b' }), SCOPE_B).resolve('secret/X', { exact: true });

    const innerA = createMockBackend({});
    const innerB = createMockBackend({});
    expect(await inScope(innerA, SCOPE_A).resolve('secret/X', { exact: true })).toEqual({ 'secret/X': 'held-by-a' });
    expect(await inScope(innerB, SCOPE_B).resolve('secret/X', { exact: true })).toEqual({ 'secret/X': 'held-by-b' });
    expect(innerA.resolveCalls + innerB.resolveCalls).toBe(0);
  });

  it('a backend built without a scope is scoped by what it names: its kind and its store', async () => {
    const named = (store: string): WritableSecretBackend & { resolveCalls: number } =>
      Object.assign(createMockBackend({ 'secret/X': `held-in-${store}` }), {
        describeStore: () => [['store', store] as const],
      });

    await new CachedBackend(named('one'), { ttlMs: 60_000, storeDir: dir }).resolve('secret/X', { exact: true });

    const sameStore = named('one');
    await new CachedBackend(sameStore, { ttlMs: 60_000, storeDir: dir }).resolve('secret/X', { exact: true });
    expect(sameStore.resolveCalls).toBe(0);

    const otherStore = named('two');
    expect(
      await new CachedBackend(otherStore, { ttlMs: 60_000, storeDir: dir }).resolve('secret/X', { exact: true }),
    ).toEqual({ 'secret/X': 'held-in-two' });
    expect(otherStore.resolveCalls).toBe(1);
  });
});
