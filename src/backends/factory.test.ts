import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import { execFileSync } from 'child_process';
import { createBackend, isKeychainAvailable, unavailableBackendError } from './factory';
import type { BackendRole } from './factory';
import { CachedBackend, cacheScope } from './cache';
import { writeBackendConfig } from './config';
import { LocalBackend } from './local';
import { MacOSKeychainBackend } from './keychain-macos';
import { LinuxKeychainBackend } from './keychain-linux';
import { OnePasswordBackend } from './onepassword';
import { VaultBackend } from './vault';
import { GCPSecretManagerBackend } from './gcp-sm';
import { fakeSecretManager, type FakeSecretManager } from './gcp-sm-fake.test-support';
import type { SecretBackend, WritableSecretBackend } from './types';

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

/** A token built at run time, shaped like no provider's. */
function runtimeToken(label: string): string {
  return [label, 'test', crypto.randomBytes(12).toString('hex')].join('-');
}

function sha256Hex(text: string): string {
  return crypto.createHash('sha256').update(text, 'utf-8').digest('hex');
}

/** Every file under `dir`, at any depth. */
function filesUnder(dir: string): string[] {
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(dir, entry.name);
    return entry.isDirectory() ? filesUnder(full) : [full];
  });
}

/**
 * The value cache's file in `dir`, decrypted. This mirrors the cache's key
 * derivation deliberately, as cache.test.ts's writeCacheFile does: it reads an
 * output for a census, and a changed derivation fails the census loudly.
 */
function decryptedCacheText(dir: string): string {
  const salt = fs.readFileSync(path.join(dir, '.salt'));
  const home = process.env.HOME ?? process.env.USERPROFILE ?? '/tmp';
  const keyMaterial = `${home}-secretless-cache-${process.env.USER ?? 'default'}`;
  const key = crypto.scryptSync(keyMaterial, salt, 32, { N: 16384, r: 8, p: 1 });
  const data = fs.readFileSync(path.join(dir, '.secret-cache'));
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, data.subarray(0, 16));
  decipher.setAuthTag(data.subarray(16, 32));
  return decipher.update(data.subarray(32)) + decipher.final('utf-8');
}

/**
 * The value cache is one file per user, shared by every shell. These build the
 * configured backend with the real factory under a home of their own, as two
 * shells whose environments name different stores or credentials would, with
 * Vault and Secret Manager played by in-process stubs: no request leaves the
 * process. A token is reported by its label (T1, T2), never by its value.
 */
describe('createBackend: the value cache serves an entry only to a read in the store scope and identity that wrote it', () => {
  const ADDR_A = 'http://127.0.0.1:8201';
  const ADDR_B = 'http://127.0.0.1:8202';
  const saved = {
    HOME: process.env.HOME,
    VAULT_ADDR: process.env.VAULT_ADDR,
    VAULT_TOKEN: process.env.VAULT_TOKEN,
    VAULT_NAMESPACE: process.env.VAULT_NAMESPACE,
    GOOGLE_APPLICATION_CREDENTIALS: process.env.GOOGLE_APPLICATION_CREDENTIALS,
    OP_ACCOUNT: process.env.OP_ACCOUNT,
    OP_SERVICE_ACCOUNT_TOKEN: process.env.OP_SERVICE_ACCOUNT_TOKEN,
  };
  let root: string;
  let tokenT1: string;
  let tokenT2: string;
  /** What each Vault holds, by address, and the tokens it lets read and write. */
  let vaults: Record<string, { held: Record<string, string>; readers: string[] }>;
  /** Every Vault request, as the address and the label of the token it carried. */
  let vaultRequests: Array<{ addr: string; token: string }>;

  /** A Vault KV v2 server at each address in `vaults`, refusing other tokens. */
  function vaultFetch() {
    const json = (status: number, body: unknown = {}) => ({ ok: status < 300, status, json: async () => body });
    return vi.fn(async (url: string, init: { method?: string; headers?: Record<string, string>; body?: string } = {}) => {
      const { origin, pathname } = new URL(url);
      const token = init.headers?.['X-Vault-Token'];
      vaultRequests.push({ addr: origin, token: token === tokenT1 ? 'T1' : token === tokenT2 ? 'T2' : 'other' });
      const vault = vaults[origin];
      if (!vault) throw new Error('no Vault answers at this address');
      if (token === undefined || !vault.readers.includes(token)) return json(403, { errors: ['permission denied'] });
      const method = init.method ?? 'GET';
      const data = /^\/v1\/secret\/data\/(.+)$/.exec(pathname)?.[1];
      if (data !== undefined && method === 'GET') {
        const name = decodeURIComponent(data);
        return name in vault.held ? json(200, { data: { data: { value: vault.held[name] } } }) : json(404);
      }
      if (data !== undefined && method === 'POST') {
        vault.held[decodeURIComponent(data)] = (JSON.parse(init.body ?? '{}') as { data: { value: string } }).data.value;
        return json(200, { data: { version: 1 } });
      }
      const metadata = /^\/v1\/secret\/metadata\/(.+)$/.exec(pathname)?.[1];
      if (metadata !== undefined && method === 'LIST') {
        const under = `${decodeURIComponent(metadata)}/`;
        const keys = Object.keys(vault.held)
          .filter((name) => name.startsWith(under) && !name.slice(under.length).includes('/'))
          .map((name) => name.slice(under.length));
        return keys.length > 0 ? json(200, { data: { keys } }) : json(404);
      }
      throw new Error(`no Vault route for ${method} ${pathname}`);
    });
  }

  /** The configured Vault backend, as a shell with this address and token builds it. */
  function vaultShell(addr: string, token: string): WritableSecretBackend {
    process.env.VAULT_ADDR = addr;
    process.env.VAULT_TOKEN = token;
    return createBackend('vault');
  }

  beforeEach(() => {
    root = tmpDir();
    process.env.HOME = path.join(root, 'home');
    fs.mkdirSync(process.env.HOME);
    delete process.env.VAULT_NAMESPACE;
    delete process.env.GOOGLE_APPLICATION_CREDENTIALS;
    delete process.env.OP_ACCOUNT;
    delete process.env.OP_SERVICE_ACCOUNT_TOKEN;
    tokenT1 = runtimeToken('t1');
    tokenT2 = runtimeToken('t2');
    vaults = {
      [ADDR_A]: { held: { 'secret/X': 'held-at-address-a' }, readers: [tokenT1] },
      [ADDR_B]: { held: { 'secret/X': 'held-at-address-b' }, readers: [tokenT1] },
    };
    vaultRequests = [];
    vi.stubGlobal('fetch', vaultFetch());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    cleanup(root);
  });

  it('(a) a value cached from one Vault address is not served to a read made against another', async () => {
    const a = vaultShell(ADDR_A, tokenT1);
    expect(a.name).toBe('cached(vault)');
    expect(await a.resolve('secret/X', { exact: true })).toEqual({ 'secret/X': 'held-at-address-a' });

    const b = vaultShell(ADDR_B, tokenT1);
    expect(await b.resolve('secret/X', { exact: true })).toEqual({ 'secret/X': 'held-at-address-b' });
    expect(vaultRequests.filter((r) => r.addr === ADDR_B)).toHaveLength(1);
  });

  it('(b) a value cached under one Vault token is not served to a read made with another: the store answers it', async () => {
    expect(await vaultShell(ADDR_A, tokenT1).resolve('secret/X', { exact: true })).toEqual({
      'secret/X': 'held-at-address-a',
    });

    const outcome = await vaultShell(ADDR_A, tokenT2).resolve('secret/X', { exact: true }).then(
      () => 'served',
      (err: Error) => (/permission denied/.test(err.message) ? 'refused by the store' : 'failed otherwise'),
    );
    expect(outcome).toBe('refused by the store');
    expect(vaultRequests.filter((r) => r.token === 'T2')).toHaveLength(1);
  });

  it('a value cached in one Vault namespace is not served to a read in another', async () => {
    await vaultShell(ADDR_A, tokenT1).resolve('secret/X', { exact: true });
    process.env.VAULT_NAMESPACE = 'team-b';
    await vaultShell(ADDR_A, tokenT1).resolve('secret/X', { exact: true });
    expect(vaultRequests).toHaveLength(2);
  });

  it('(e) CONTROL: the same Vault address and token are served from the cache, with no request', async () => {
    await vaultShell(ADDR_A, tokenT1).resolve('secret/X', { exact: true });
    expect(vaultRequests).toHaveLength(1);

    expect(await vaultShell(ADDR_A, tokenT1).resolve('secret/X', { exact: true })).toEqual({
      'secret/X': 'held-at-address-a',
    });
    // The same server, written with the trailing slash another shell may give it.
    expect(await vaultShell(`${ADDR_A}/`, tokenT1).resolve('secret/X', { exact: true })).toEqual({
      'secret/X': 'held-at-address-a',
    });
    expect(vaultRequests).toHaveLength(1);
  });

  it('every backend the factory caches names its store and the identity it reads with: another one is another scope', () => {
    // Booleans only, so a failure prints no scope.
    const differ = (a: SecretBackend, b: SecretBackend): boolean => cacheScope(a) !== cacheScope(b);
    const dirA = path.join(root, 'store-a');
    const dirB = path.join(root, 'store-b');

    expect(differ(new MacOSKeychainBackend({ storeDir: dirA }), new MacOSKeychainBackend({ storeDir: dirA }))).toBe(false);
    expect(differ(new MacOSKeychainBackend({ storeDir: dirA }), new MacOSKeychainBackend({ storeDir: dirB }))).toBe(true);
    expect(differ(new LinuxKeychainBackend({ storeDir: dirA }), new LinuxKeychainBackend({ storeDir: dirB }))).toBe(true);
    expect(differ(new LocalBackend({ storeDir: dirA, key: 'test' }), new LocalBackend({ storeDir: dirB, key: 'test' }))).toBe(true);
    // One directory, read as the keychain's index and as the encrypted file: the kind differs.
    expect(differ(new MacOSKeychainBackend({ storeDir: dirA }), new LocalBackend({ storeDir: dirA, key: 'test' }))).toBe(true);

    expect(differ(new OnePasswordBackend({ vault: 'Team' }), new OnePasswordBackend({ vault: 'Team' }))).toBe(false);
    expect(differ(new OnePasswordBackend({ vault: 'Team' }), new OnePasswordBackend({ vault: 'Personal' }))).toBe(true);
    const onePassword = new OnePasswordBackend({ vault: 'Team' });
    const signedIn = cacheScope(onePassword);
    process.env.OP_ACCOUNT = 'second-account.example';
    expect(cacheScope(onePassword) !== signedIn).toBe(true);
    delete process.env.OP_ACCOUNT;
    process.env.OP_SERVICE_ACCOUNT_TOKEN = runtimeToken('service-account');
    expect(cacheScope(onePassword) !== signedIn).toBe(true);

    const vaultAt = (addr: string, token = tokenT1, mountPath?: string): VaultBackend =>
      new VaultBackend({ addr, token, mountPath });
    expect(differ(vaultAt('https://vault.example.test'), vaultAt('HTTPS://Vault.Example.Test:443/'))).toBe(false);
    expect(differ(vaultAt('https://vault.example.test'), vaultAt('https://vault.example.test:8200'))).toBe(true);
    expect(differ(vaultAt('https://vault.example.test'), vaultAt('https://vault.example.test', tokenT2))).toBe(true);
    expect(differ(vaultAt('https://vault.example.test'), vaultAt('https://vault.example.test', tokenT1, 'kv'))).toBe(true);

    // A gcp-sm backend that cannot name its project yet gets a scope no other
    // backend has; one project read with one credential is one scope.
    const gcpIn = (projectId?: string): GCPSecretManagerBackend =>
      new GCPSecretManagerBackend({ projectId, projectDir: path.join(root, 'no-manifest') });
    expect(differ(gcpIn(), gcpIn())).toBe(true);
    expect(differ(gcpIn('project-a'), gcpIn('project-a'))).toBe(false);
    expect(differ(gcpIn('project-a'), gcpIn('project-b'))).toBe(true);
  });

  it('(h) census: no file under the store directory holds a token or its digest, and the decrypted cache holds neither', async () => {
    const shell = vaultShell(ADDR_A, tokenT1);
    await shell.resolve('secret/X', { exact: true });
    await shell.store('secret/W', 'stored-through-the-cache');
    await shell.resolve('secret');
    await vaultShell(ADDR_B, tokenT1).resolve('secret/X', { exact: true });
    await vaultShell(ADDR_A, tokenT2).resolve('secret/X', { exact: true }).catch(() => undefined);

    const storeRoot = path.join(process.env.HOME ?? '', '.secretless-ai');
    const files = filesUnder(storeRoot);
    const tokensAndDigests = [tokenT1, tokenT2].flatMap((token) => [token, sha256Hex(token)]);
    const decryptedText = decryptedCacheText(path.join(storeRoot, 'cache'));
    const entries = (JSON.parse(decryptedText) as { entries: Record<string, { scope?: unknown }> }).entries;
    const scopes = [...new Set(Object.values(entries).map((entry) => entry.scope))].filter(
      (scope): scope is string => typeof scope === 'string',
    );
    const holdsAny = (file: string, needles: string[]): boolean => {
      const bytes = fs.readFileSync(file);
      return needles.some((needle) => bytes.includes(needle));
    };
    const census = {
      files: files.length,
      filesHoldingATokenOrItsDigest: files.filter((file) => holdsAny(file, tokensAndDigests)).length,
      filesHoldingAScopeInClear: files.filter((file) => holdsAny(file, scopes)).length,
      tokensOrDigestsInTheDecryptedCache: tokensAndDigests.filter((needle) => decryptedText.includes(needle)).length,
      entries: Object.keys(entries).filter((key) => !key.includes('__resolved__')).length,
      markers: Object.keys(entries).filter((key) => key.includes('__resolved__')).length,
      entriesOrMarkersWithoutAScope: Object.values(entries).filter((entry) => typeof entry.scope !== 'string').length,
      scopes: scopes.length,
    };
    // Counts only: no token, digest or scope is printed, here or by a failure.
    console.log(`census ${JSON.stringify(census)}`);

    expect(census.files).toBeGreaterThan(0);
    expect(census.filesHoldingATokenOrItsDigest).toBe(0);
    expect(census.filesHoldingAScopeInClear).toBe(0);
    expect(census.tokensOrDigestsInTheDecryptedCache).toBe(0);
    expect(census.entries).toBeGreaterThan(0);
    expect(census.markers).toBeGreaterThan(0);
    expect(census.entriesOrMarkersWithoutAScope).toBe(0);
    // Address A with T1 and address B with T1; T2 was refused and cached nothing.
    expect(census.scopes).toBe(2);
  });

  describe('gcp-sm', () => {
    let projects: Record<string, FakeSecretManager>;
    let workDir: string;

    beforeEach(() => {
      projects = { 'project-a': fakeSecretManager('project-a'), 'project-b': fakeSecretManager('project-b') };
      projects['project-a'].put('STRIPE_KEY', 'held-in-project-a');
      projects['project-b'].put('STRIPE_KEY', 'held-in-project-b');
      workDir = path.join(root, 'work');
      fs.mkdirSync(workDir);
      vi.stubGlobal('fetch', vi.fn(async (url: string, init?: { method?: string; body?: string }) => {
        const project = /^\/v1\/projects\/([^/]+)\//.exec(new URL(url).pathname)?.[1];
        const fake = project === undefined ? undefined : projects[project];
        if (!fake) throw new Error('no Secret Manager project answers this request');
        return fake.fetch(url, init);
      }));
    });

    /** A service account key file naming a project and an account. It holds no key. */
    function keyFile(name: string, projectId: string, clientEmail: string): string {
      const file = path.join(root, `${name}.json`);
      fs.writeFileSync(
        file,
        JSON.stringify({ type: 'service_account', project_id: projectId, client_email: clientEmail }),
        { mode: 0o600 },
      );
      return file;
    }

    /**
     * The configured gcp-sm backend, as a shell whose GOOGLE_APPLICATION_CREDENTIALS
     * names `keyPath` (or no key file) builds it, in a directory with no
     * .secretless. Its access token is primed, as the backend's own tests prime
     * it, so no token request is made.
     */
    function gcpShell(keyPath: string | undefined): WritableSecretBackend {
      if (keyPath === undefined) delete process.env.GOOGLE_APPLICATION_CREDENTIALS;
      else process.env.GOOGLE_APPLICATION_CREDENTIALS = keyPath;
      const backend = createBackend('gcp-sm', { projectDir: workDir });
      const inner = (backend as unknown as { inner?: object }).inner ?? backend;
      Object.assign(inner, { accessToken: runtimeToken('access'), tokenExpiry: Date.now() + 3_600_000 });
      return backend;
    }

    it('(f) a value cached from one project named by the environment is not served to a read in another', async () => {
      const account = 'reader@example-project.iam.gserviceaccount.com';
      const a = gcpShell(keyFile('key-a', 'project-a', account));
      expect(a.name).toBe('cached(gcp-sm)');
      expect(await a.resolve('secret/STRIPE_KEY', { exact: true })).toEqual({
        'secret/STRIPE_KEY': 'held-in-project-a',
      });

      const b = gcpShell(keyFile('key-b', 'project-b', account));
      expect(await b.resolve('secret/STRIPE_KEY', { exact: true })).toEqual({
        'secret/STRIPE_KEY': 'held-in-project-b',
      });
      expect(projects['project-b'].valueReads).toEqual(['STRIPE_KEY']);
    });

    it('a value cached by one service account is not served to a read made as another, in the same project', async () => {
      await gcpShell(keyFile('key-one', 'project-a', 'reader-one@example-project.iam.gserviceaccount.com'))
        .resolve('secret/STRIPE_KEY', { exact: true });
      await gcpShell(keyFile('key-two', 'project-a', 'reader-two@example-project.iam.gserviceaccount.com'))
        .resolve('secret/STRIPE_KEY', { exact: true });
      expect(projects['project-a'].valueReads).toEqual(['STRIPE_KEY', 'STRIPE_KEY']);
    });

    it('a value cached under one Application Default Credentials login is not served after a login as another', async () => {
      const adc = path.join(process.env.HOME ?? '', '.config', 'gcloud', 'application_default_credentials.json');
      fs.mkdirSync(path.dirname(adc), { recursive: true });
      const login = (grant: string): void => {
        fs.writeFileSync(
          adc,
          JSON.stringify({ type: 'authorized_user', account: '', quota_project_id: 'project-a', refresh_token: grant }),
          { mode: 0o600 },
        );
      };

      login(runtimeToken('grant-one'));
      await gcpShell(undefined).resolve('secret/STRIPE_KEY', { exact: true });
      await gcpShell(undefined).resolve('secret/STRIPE_KEY', { exact: true });
      expect(projects['project-a'].valueReads).toEqual(['STRIPE_KEY']);

      login(runtimeToken('grant-two'));
      await gcpShell(undefined).resolve('secret/STRIPE_KEY', { exact: true });
      expect(projects['project-a'].valueReads).toEqual(['STRIPE_KEY', 'STRIPE_KEY']);
    });

    it('(e) CONTROL: the same project and service account are served from the cache, with no request', async () => {
      const key = keyFile('key-a', 'project-a', 'reader@example-project.iam.gserviceaccount.com');
      await gcpShell(key).resolve('secret/STRIPE_KEY', { exact: true });
      const requests = projects['project-a'].requests.length;

      expect(await gcpShell(key).resolve('secret/STRIPE_KEY', { exact: true })).toEqual({
        'secret/STRIPE_KEY': 'held-in-project-a',
      });
      expect(projects['project-a'].requests).toHaveLength(requests);
    });
  });
});
