import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { resolveRef } from './resolver';
import { CachedBackend } from '../backends/cache';
import { writeBackendConfig } from '../backends/config';
import { LocalBackend } from '../backends/local';

/**
 * #369: a `secret://` reference that names a backend was resolved behind the
 * shared value cache whatever store this machine uses. That file is keyed by
 * entry name alone, so with a keychain configured, `secret://vault/STRIPE_KEY`
 * cached what Vault held and the next read of `STRIPE_KEY` was answered with
 * it as the keychain's value; and a value the keychain had cached answered the
 * reference in Vault's place.
 *
 * These run the real factory and the real cache file under a home of their
 * own. The configured store is played by a `CachedBackend` over a local store
 * on the default cache file, which is what `createBackend` wraps the configured
 * backend in: no OS keychain is asked for anything.
 */
describe('resolveRef: a reference naming a backend and the shared value cache (#369)', () => {
  const HELD = 'held-by-vault-only';
  const saved = {
    HOME: process.env.HOME,
    PATH: process.env.PATH,
    VAULT_ADDR: process.env.VAULT_ADDR,
    VAULT_TOKEN: process.env.VAULT_TOKEN,
  };
  let root: string;
  let vault: Record<string, string>;
  let vaultRequests: ReturnType<typeof vaultServer>;

  /** A Vault KV v2 server holding `secret/<name>` for each name in `vault`. */
  function vaultServer() {
    const json = (status: number, body: unknown) => ({ ok: status < 300, status, json: async () => body });
    return vi.fn(async (url: string, init: { method: string }) => {
      const name = /^\/v1\/secret\/data\/secret\/(.+)$/.exec(new URL(url).pathname)?.[1];
      if (name !== undefined && init.method === 'GET' && name in vault) {
        return json(200, { data: { data: { value: vault[name] } } });
      }
      return json(404, { errors: [] });
    });
  }

  /** The configured store's cache layer, over a store holding `held`. */
  async function configuredStoreCache(held: Record<string, string> = {}): Promise<CachedBackend> {
    const store = new LocalBackend({ storeDir: path.join(root, 'configured-store'), key: 'test' });
    for (const [key, value] of Object.entries(held)) await store.store(key, value);
    return new CachedBackend(store);
  }

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-resolver-cache-test-'));
    const home = path.join(root, 'home');
    const bin = path.join(root, 'bin');
    fs.mkdirSync(home);
    fs.mkdirSync(bin);
    // A `secret-tool` stand-in, so a Linux runner sees a likely keychain as
    // macOS always does. Nothing here starts it.
    fs.writeFileSync(path.join(bin, 'secret-tool'), '#!/bin/sh\nexit 1\n', { mode: 0o755 });
    process.env.HOME = home;
    process.env.PATH = `${bin}${path.delimiter}${saved.PATH ?? ''}`;
    process.env.VAULT_ADDR = 'http://127.0.0.1:1';
    process.env.VAULT_TOKEN = 'not-a-real-token';
    vault = { STRIPE_KEY: HELD };
    vaultRequests = vaultServer();
    vi.stubGlobal('fetch', vaultRequests);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    fs.rmSync(root, { recursive: true, force: true });
  });

  it.each([
    ['a configured keychain', 'keychain'],
    ['a configured encrypted file', 'local'],
    ['no configured backend', undefined],
  ] as const)(
    'beside %s, a value read through a reference naming vault is not served as the configured store\'s',
    async (_label, configured) => {
      if (configured !== undefined) writeBackendConfig(configured);
      expect((await resolveRef('secret://vault/STRIPE_KEY')).value).toBe(HELD);

      // Before the fix this answered { 'secret/STRIPE_KEY': HELD } from the
      // cache, without asking the store it wraps.
      const store = await configuredStoreCache();
      expect(await store.resolve('secret/STRIPE_KEY')).toEqual({});
      expect(await store.resolve('secret')).toEqual({});
    },
  );

  it('a reference naming vault is answered by vault, not by what the configured store cached under that name', async () => {
    writeBackendConfig('keychain');
    const store = await configuredStoreCache({ 'secret/STRIPE_KEY': 'held-by-the-configured-store' });
    expect(await store.resolve('secret/STRIPE_KEY')).toEqual({
      'secret/STRIPE_KEY': 'held-by-the-configured-store',
    });
    expect(store.getCacheStats().entries).toBe(1);

    // Before the fix this was 'held-by-the-configured-store', and Vault was
    // never asked.
    expect((await resolveRef('secret://vault/STRIPE_KEY')).value).toBe(HELD);
    expect(vaultRequests).toHaveBeenCalledTimes(1);
    // The configured store's cached value is still its own.
    expect(await (await configuredStoreCache()).resolve('secret/STRIPE_KEY')).toEqual({
      'secret/STRIPE_KEY': 'held-by-the-configured-store',
    });
  });

  it('a reference naming vault asks vault each time beside another configured store', async () => {
    writeBackendConfig('keychain');
    await resolveRef('secret://vault/STRIPE_KEY');
    vault.STRIPE_KEY = 'rotated-in-vault';
    expect((await resolveRef('secret://vault/STRIPE_KEY')).value).toBe('rotated-in-vault');
    expect(vaultRequests).toHaveBeenCalledTimes(2);
  });

  it('keeps the cache layer when the reference names the configured backend, whose values the cache holds', async () => {
    writeBackendConfig('vault');
    expect((await resolveRef('secret://vault/STRIPE_KEY')).value).toBe(HELD);
    expect(vaultRequests).toHaveBeenCalledTimes(1);

    // The second read is answered from the cache: Vault is not asked again.
    expect((await resolveRef('secret://vault/STRIPE_KEY')).value).toBe(HELD);
    expect(vaultRequests).toHaveBeenCalledTimes(1);
    expect((await configuredStoreCache()).getCacheStats().entries).toBe(1);
  });
});
