import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { execFileSync } from 'child_process';
import { createBackend, isKeychainAvailable, unavailableBackendError } from './factory';
import type { BackendRole } from './factory';
import { CachedBackend } from './cache';
import { writeBackendConfig } from './config';
import { LocalBackend } from './local';

vi.mock('child_process', async (importOriginal) => {
  const actual = await importOriginal<typeof import('child_process')>();
  return { ...actual, execFileSync: vi.fn() };
});

const mockExec = execFileSync as unknown as ReturnType<typeof vi.fn>;

/**
 * Reproduce the machine state that motivated this suite: the `op` BINARY is
 * installed and an account is configured locally, but the 1Password desktop app
 * is not connected, so any command needing the app fails.
 *
 * Measured on a real machine 2026-08-05 (op 2.32.1):
 *   op --version                 -> exit 0
 *   op account list              -> exit 0   (answers from local config)
 *   op account get --format json -> exit 1   (needs the app)
 *   op vault list                -> exit 1
 *
 * The `account list` / `account get` split matters: a probe that used the
 * former would call this machine healthy.
 */
function mockOpInstalledButAppDisconnected(): void {
  mockExec.mockImplementation((cmd: string, args: string[] = []) => {
    if (cmd !== 'op') return '';
    if (args[0] === '--version') return '2.32.1\n';
    if (args[0] === 'account' && args[1] === 'list') return 'my.1password.com\n';
    throw new Error(
      "connecting to desktop app: 1Password CLI couldn't connect to the 1Password desktop app.",
    );
  });
}

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-factory-test-'));
}

function cleanup(dir: string): void {
  fs.rmSync(dir, { recursive: true, force: true });
}

describe('createBackend', () => {
  let dir: string;

  afterEach(() => {
    if (dir) cleanup(dir);
  });

  it('creates LocalBackend for "local" type', () => {
    dir = tmpDir();
    const backend = createBackend('local', { storeDir: dir, key: 'test' });
    expect(backend.name).toBe('local');
    expect(backend).toBeInstanceOf(LocalBackend);
  });

  it('creates a keychain backend for "keychain" type', () => {
    dir = tmpDir();
    const backend = createBackend('keychain', { storeDir: dir });
    // On macOS it should be keychain-macos, on Linux keychain-linux
    // On other platforms it falls back to local
    // With default cache TTL > 0, keychain backends get wrapped in CachedBackend
    const validNames = [
      'keychain-macos', 'keychain-linux', 'local',
      'cached(keychain-macos)', 'cached(keychain-linux)', 'cached(local)',
    ];
    expect(validNames).toContain(backend.name);
  });
});

/**
 * Regression cover for the silent store-substitution bug.
 *
 * Before the fix, an unreachable configured backend returned a LocalBackend and
 * only warned on stderr. `secret set` then wrote to a store the user never
 * chose and printed "Stored: NAME", and `backend purge` would have deleted from
 * that other store. These tests fail on the pre-fix factory, which returned
 * LocalBackend here instead of throwing.
 */
describe('createBackend: unreachable configured backend fails closed', () => {
  beforeEach(() => {
    mockExec.mockReset();
  });

  afterEach(() => {
    delete process.env.VAULT_ADDR;
    delete process.env.VAULT_TOKEN;
  });

  it('throws instead of substituting local when 1Password is unreachable', () => {
    mockOpInstalledButAppDisconnected();
    expect(() => createBackend('1password')).toThrow(/not reachable/i);
  });

  it('never hands back a different store for an unreachable 1Password', () => {
    mockOpInstalledButAppDisconnected();
    let returned: unknown;
    try {
      returned = createBackend('1password');
    } catch {
      returned = undefined;
    }
    // The pre-fix code reached here holding a LocalBackend.
    expect(returned).toBeUndefined();
  });

  it('names the configured backend and gives verify + fix commands, not a dead end', () => {
    mockOpInstalledButAppDisconnected();
    let message = '';
    try {
      createBackend('1password');
    } catch (err) {
      message = (err as Error).message;
    }
    expect(message).toContain('1password');
    expect(message).toMatch(/Verify:\s+op account get/);
    expect(message).toMatch(/Fix:\s+brew install 1password-cli/);
    // The reassurance is load-bearing: this fires while a user is mid-command.
    expect(message).toMatch(/secrets are safe/i);
    // It must NOT claim it used another store.
    expect(message).not.toMatch(/using local backend instead/i);
  });

  it('throws for an unconfigured Vault backend rather than substituting local', () => {
    expect(() => createBackend('vault')).toThrow(/not reachable/i);
  });

  it('builds the Vault backend once its environment is present', () => {
    process.env.VAULT_ADDR = 'https://vault.example.com';
    process.env.VAULT_TOKEN = 'test-token';
    expect(() => createBackend('vault')).not.toThrow();
  });

  it('still degrades for read-only diagnostics that opt in explicitly', () => {
    mockOpInstalledButAppDisconnected();
    const scratch = tmpDir();
    try {
      const backend = createBackend('1password', { storeDir: scratch, key: 'test' }, false);
      expect(backend).toBeInstanceOf(LocalBackend);
    } finally {
      cleanup(scratch);
    }
  });
});

describe('isKeychainAvailable', () => {
  it('returns platform information', () => {
    const result = isKeychainAvailable();
    expect(result).toHaveProperty('available');
    expect(result).toHaveProperty('platform');
    expect(result).toHaveProperty('message');
    expect(typeof result.available).toBe('boolean');
    expect(typeof result.platform).toBe('string');
    expect(typeof result.message).toBe('string');
  });

  it('returns correct platform name', () => {
    const result = isKeychainAvailable();
    if (process.platform === 'darwin') {
      expect(result.platform).toBe('macOS');
    } else if (process.platform === 'linux') {
      expect(result.platform).toBe('Linux');
    }
  });
});

describe('unavailableBackendError formatting', () => {
  it('keeps the Verify/Fix block intact when the reason carries newlines', () => {
    const err = unavailableBackendError(
      '1password',
      'line one\nline two\n  indented three',
      ['do the thing'],
      'op account get',
    );
    const lines = err.message.split('\n');
    // The reason must occupy exactly one line, or everything below it stops
    // reading as a list.
    expect(lines[0]).toBe(
      'Configured backend "1password" is not reachable: line one line two indented three',
    );
    expect(err.message).toMatch(/^  Verify:  op account get$/m);
    expect(err.message).toMatch(/^  Fix:     do the thing$/m);
  });

  it('names a backend chosen with --backend as that, and offers no migration (#365)', () => {
    const err = unavailableBackendError(
      '1password',
      '1Password CLI (op) not found.',
      ['brew install 1password-cli && op signin'],
      'op account get',
      'named',
    );
    expect(err.message.split('\n')[0]).toBe(
      'Backend "1password", named with --backend, is not reachable: 1Password CLI (op) not found.',
    );
    expect(err.message).not.toContain('Configured backend');
    expect(err.message).not.toContain('migrate');
    expect(err.message).toMatch(/^  Verify:  op account get$/m);
    expect(err.message).toMatch(/^  Fix:     brew install 1password-cli && op signin$/m);
    expect(err.message).toContain('run the command again without --backend');
  });

  it('tells a backend named with --backend that no other store was touched, as it tells the configured one (#367)', () => {
    const message = (role: BackendRole): string =>
      unavailableBackendError('vault', 'VAULT_ADDR and VAULT_TOKEN must be set', [], 'vault token lookup', role).message;
    const assurance = '  Your secrets are safe. Nothing was read from or written to another store.';
    expect(message('named').split('\n')).toContain(assurance);
    expect(message('configured').split('\n')).toContain(assurance);
    // CONTROL: a source is only read, so it is told something else.
    expect(message('source')).not.toContain('another store');
    expect(message('named')).not.toContain('Nothing was read from it');
  });
});

/**
 * #367: `setup --backend` built the backend it names behind the shared value
 * cache. That file is keyed by entry name alone, so `setup --check --backend
 * vault` cached what Vault held, and `setup --check` then counted those names
 * as satisfied by a configured keychain that held none of them.
 *
 * The configured store is played by a `CachedBackend` over an empty store on
 * the default cache file, which is what `createBackend` wraps the configured
 * backend in: no OS keychain is asked for anything.
 */
describe('createBackend: a backend named for one run and the shared value cache (#367)', () => {
  const HELD = 'held-by-vault-only';
  const saved = {
    HOME: process.env.HOME,
    PATH: process.env.PATH,
    VAULT_ADDR: process.env.VAULT_ADDR,
    VAULT_TOKEN: process.env.VAULT_TOKEN,
  };
  let root: string;
  let vault: Record<string, string>;

  /** A Vault KV v2 server holding `secret/<name>` for each name in `vault`. */
  function vaultServer() {
    const json = (status: number, body: unknown) => ({ ok: status < 300, status, json: async () => body });
    return vi.fn(async (url: string, init: { method: string; body?: string }) => {
      const { pathname } = new URL(url);
      if (init.method === 'LIST' && pathname === '/v1/secret/metadata/secret') {
        return json(200, { data: { keys: Object.keys(vault) } });
      }
      const name = /^\/v1\/secret\/data\/secret\/(.+)$/.exec(pathname)?.[1];
      if (name !== undefined && init.method === 'POST') {
        vault[name] = (JSON.parse(init.body ?? '{}') as { data: { value: string } }).data.value;
        return json(200, { data: { version: 1 } });
      }
      if (name !== undefined && init.method === 'GET' && name in vault) {
        return json(200, { data: { data: { value: vault[name] } } });
      }
      return json(404, { errors: [] });
    });
  }

  /** The configured store's cache layer, over a store that holds nothing. */
  function configuredStoreCache(): CachedBackend {
    return new CachedBackend(new LocalBackend({ storeDir: path.join(root, 'empty-store'), key: 'test' }));
  }

  beforeEach(() => {
    root = tmpDir();
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
    vi.stubGlobal('fetch', vaultServer());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    cleanup(root);
  });

  it('a value read through a named backend is not served as the configured store\'s', async () => {
    writeBackendConfig('keychain');
    const named = createBackend('vault', undefined, true, { role: 'named' });
    expect(await named.resolve('secret')).toEqual({ 'secret/STRIPE_KEY': HELD });

    // Before the fix this answered { 'secret/STRIPE_KEY': HELD } from the
    // cache, without asking the store it wraps.
    expect(await configuredStoreCache().resolve('secret')).toEqual({});
    expect(configuredStoreCache().getCacheStats().entries).toBe(0);
  });

  it('a value written through a named backend is not left in the cache', async () => {
    writeBackendConfig('keychain');
    const named = createBackend('vault', undefined, true, { role: 'named' });
    await named.store('secret/DATABASE_URL', 'typed-into-setup');
    expect(vault.DATABASE_URL).toBe('typed-into-setup');
    expect(configuredStoreCache().getCacheStats().entries).toBe(0);
  });

  it('CONTROL: the same read through the default role is cached, so the two tests above can fail', async () => {
    writeBackendConfig('keychain');
    await createBackend('vault').resolve('secret');
    expect(configuredStoreCache().getCacheStats().entries).toBe(1);
  });

  it('is built without the cache layer beside a different configured backend, and beside the default', () => {
    const name = (): string => createBackend('vault', undefined, true, { role: 'named' }).name;
    expect(name()).toBe('vault');
    writeBackendConfig('keychain');
    expect(name()).toBe('vault');
    writeBackendConfig('local');
    expect(name()).toBe('vault');
  });

  it('keeps the cache layer when it names the configured backend, whose values the cache holds', async () => {
    writeBackendConfig('vault');
    const named = createBackend('vault', undefined, true, { role: 'named' });
    expect(named.name).toBe('cached(vault)');

    // What that is for: a write through --backend reaches the next read
    // without --backend. Uncached, the list cached before it would be served.
    const configured = createBackend('vault');
    expect(Object.keys(await configured.resolve('secret'))).toEqual(['secret/STRIPE_KEY']);
    await named.store('secret/DATABASE_URL', 'typed-into-setup');
    expect(Object.keys(await createBackend('vault').resolve('secret')).sort()).toEqual([
      'secret/DATABASE_URL',
      'secret/STRIPE_KEY',
    ]);
  });

  it.skipIf(process.platform !== 'darwin' && process.platform !== 'linux')(
    'keeps the cache layer for a named keychain when no backend is configured, where the keychain is the default',
    () => {
      const unconfigured = createBackend('local').name;
      expect(unconfigured).toMatch(/^cached\(keychain-(macos|linux)\)$/);
      expect(createBackend('keychain', undefined, true, { role: 'named' }).name).toBe(unconfigured);
      // Once another backend is configured, a named keychain is a second store.
      writeBackendConfig('vault');
      expect(createBackend('keychain', undefined, true, { role: 'named' }).name).toMatch(/^keychain-(macos|linux)$/);
    },
  );
});
