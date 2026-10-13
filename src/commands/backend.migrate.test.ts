/**
 * `migrate` and the shared value cache (#370).
 *
 * `migrate --from <backend>` built its source behind the value cache. That
 * file is keyed by entry name alone and answers whichever backend asks, so the
 * migration copied what was cached under a name instead of what `--from`
 * held: the configured backend's value for the same name, or the source's own
 * value from before a rotation. A cached empty listing made it report that
 * there was nothing to migrate. Nothing removed the file afterwards either, so
 * a read through the backend the migration had just configured was answered
 * from the previous backend's entries.
 *
 * The backends here are the Vault backend over a stubbed `fetch` and the
 * encrypted file, in a temporary HOME. The configured keychain's cache layer
 * is played by a `CachedBackend` over a file store on the default cache file,
 * which is what `createBackend` wraps the configured backend in. No test
 * starts a child process: `execFileSync` raises for every program.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runBackend, runMigrate } from './backend';
import { CachedBackend } from '../backends/cache';
import { readBackendConfig, writeBackendConfig } from '../backends/config';
import { createBackend } from '../backends/factory';
import { LocalBackend } from '../backends/local';

vi.mock('child_process', async (importOriginal) => {
  const actual = await importOriginal<typeof import('child_process')>();
  return {
    ...actual,
    execFileSync: vi.fn(() => {
      throw new Error('no child process is started in this suite');
    }),
  };
});

const saved = {
  HOME: process.env.HOME,
  PATH: process.env.PATH,
  VAULT_ADDR: process.env.VAULT_ADDR,
  VAULT_TOKEN: process.env.VAULT_TOKEN,
};
let root: string;
/** What Vault holds, by name under `secret/`. */
let vault: Record<string, string>;
/** Vault answers every write with 403. */
let vaultRefusesWrites: boolean;
/** Vault answers a read of the `mcp` prefix with 500. */
let vaultFailsMcpRead: boolean;
/** When set, Vault answers the LIST of the `secret` prefix with this status. */
let vaultListStatus: number | undefined;
let out: string[];
let err: string[];

/** A Vault KV v2 server holding `secret/<name>` for each name in `vault`. */
function vaultServer() {
  const json = (status: number, body: unknown) => ({ ok: status < 300, status, json: async () => body });
  return vi.fn(async (url: string, init: { method: string; body?: string }) => {
    const { pathname } = new URL(url);
    if (vaultFailsMcpRead && pathname === '/v1/secret/data/mcp') return json(500, { errors: [] });
    if (init.method === 'LIST' && pathname === '/v1/secret/metadata/secret') {
      if (vaultListStatus !== undefined) return json(vaultListStatus, { errors: [] });
      return json(200, { data: { keys: Object.keys(vault) } });
    }
    const name = /^\/v1\/secret\/data\/secret\/(.+)$/.exec(pathname)?.[1];
    if (name !== undefined && init.method === 'POST') {
      if (vaultRefusesWrites) return json(403, { errors: ['permission denied'] });
      vault[name] = (JSON.parse(init.body ?? '{}') as { data: { value: string } }).data.value;
      return json(200, { data: { version: 1 } });
    }
    if (name !== undefined && init.method === 'GET' && name in vault) {
      // A turn of the event loop, as a server's answer takes: a copy that is
      // still running when `migrate` returns has not reached its write yet.
      await new Promise((resolve) => setImmediate(resolve));
      return json(200, { data: { data: { value: vault[name] } } });
    }
    return json(404, { errors: [] });
  });
}

/**
 * Read `entries` through the configured keychain's cache layer, as `secret
 * list` or `run` does on a machine that keeps its secrets in the keychain.
 */
async function readThroughConfiguredKeychain(entries: Record<string, string>): Promise<void> {
  const keychain = new LocalBackend({ storeDir: path.join(root, 'keychain'), key: 'test' });
  for (const [name, value] of Object.entries(entries)) await keychain.store(`secret/${name}`, value);
  await new CachedBackend(keychain).resolve('secret');
}

function cacheFile(): string {
  return path.join(root, 'home', '.secretless-ai', 'cache', '.secret-cache');
}

/** What the encrypted file holds under `secret/`. */
function fileStore(): Promise<Record<string, string>> {
  return new LocalBackend().resolve('secret');
}

beforeEach(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-migrate-test-'));
  fs.mkdirSync(path.join(root, 'home'));
  process.env.HOME = path.join(root, 'home');
  process.env.VAULT_ADDR = 'http://127.0.0.1:1';
  process.env.VAULT_TOKEN = 'not-a-real-token';
  vault = {};
  vaultRefusesWrites = false;
  vaultFailsMcpRead = false;
  vaultListStatus = undefined;
  vi.stubGlobal('fetch', vaultServer());
  out = [];
  err = [];
  vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { out.push(a.join(' ')); });
  vi.spyOn(console, 'error').mockImplementation((...a: unknown[]) => { err.push(a.join(' ')); });
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  for (const [k, v] of Object.entries(saved)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  fs.rmSync(root, { recursive: true, force: true });
});

describe('migrate reads --from itself, not the shared value cache (#370)', () => {
  it('copies the value the source holds, not the configured backend\'s value cached under the same name', async () => {
    writeBackendConfig('keychain');
    await readThroughConfiguredKeychain({ STRIPE_KEY: 'held-by-keychain' });
    vault = { STRIPE_KEY: 'held-by-vault' };

    expect(await runMigrate(['--from', 'vault', '--to', 'local'])).toBe(0);

    // Before the fix the encrypted file received 'held-by-keychain'.
    expect(await fileStore()).toEqual({ 'secret/STRIPE_KEY': 'held-by-vault' });
  });

  it('migrates what the source holds after the configured backend was listed as empty', async () => {
    writeBackendConfig('keychain');
    await readThroughConfiguredKeychain({});
    vault = { STRIPE_KEY: 'held-by-vault' };

    expect(await runMigrate(['--from', 'vault', '--to', 'local'])).toBe(0);

    // Before the fix: 'No secrets found to migrate.', and nothing was copied.
    expect(out.join('\n')).toContain('Migrated: 1 secret(s)');
    expect(await fileStore()).toEqual({ 'secret/STRIPE_KEY': 'held-by-vault' });
  });

  it('copies the value the source holds now, not the one cached from it before a rotation', async () => {
    writeBackendConfig('vault');
    vault = { STRIPE_KEY: 'before-rotation' };
    await createBackend('vault').resolve('secret');
    vault.STRIPE_KEY = 'after-rotation';

    expect(await runMigrate(['--from', 'vault', '--to', 'local'])).toBe(0);

    expect(await fileStore()).toEqual({ 'secret/STRIPE_KEY': 'after-rotation' });
  });

  it('CONTROL: the default role answers the same read from the cache, so the tests above can fail', async () => {
    writeBackendConfig('keychain');
    await readThroughConfiguredKeychain({ STRIPE_KEY: 'held-by-keychain' });
    vault = { STRIPE_KEY: 'held-by-vault' };

    expect(await createBackend('vault').resolve('secret')).toEqual({ 'secret/STRIPE_KEY': 'held-by-keychain' });
  });

  it('names an unreachable --from as the source, without offering the migration that was asked for', async () => {
    writeBackendConfig('keychain');

    const refusal = await runMigrate(['--from', '1password', '--to', 'local']).then(
      () => undefined,
      (e: Error) => e,
    );

    // Before the fix: 'Configured backend "1password" is not reachable', then
    // `secretless-ai backend migrate --from 1password --to local` as the way out.
    expect(refusal?.message.split('\n')[0]).toBe(
      'Source backend "1password" is not reachable: 1Password CLI (op) not found. Install from https://developer.1password.com/docs/cli',
    );
    expect(refusal?.message).toContain('Nothing was read from it, and nothing on this machine was changed.');
    expect(refusal?.message).not.toContain('backend migrate');
    expect(readBackendConfig()).toBe('keychain');
  });
});

describe('migrate removes the value cache when it ends (#370)', () => {
  it('after a migration, whose destination is now the configured backend', async () => {
    writeBackendConfig('keychain');
    await readThroughConfiguredKeychain({ STRIPE_KEY: 'held-by-keychain' });
    expect(fs.existsSync(cacheFile())).toBe(true);
    vault = { STRIPE_KEY: 'held-by-vault' };

    expect(await runMigrate(['--from', 'vault', '--to', 'local'])).toBe(0);

    expect(readBackendConfig()).toBe('local');
    expect(fs.existsSync(cacheFile())).toBe(false);
  });

  it('after a migration whose writes failed, so the new backend is not answered for from the old one\'s entries', async () => {
    writeBackendConfig('keychain');
    await readThroughConfiguredKeychain({ STRIPE_KEY: 'held-by-keychain' });
    await new LocalBackend().store('secret/STRIPE_KEY', 'held-by-file');
    vaultRefusesWrites = true;

    expect(await runMigrate(['--from', 'local', '--to', 'vault'])).toBe(1);

    expect(out.join('\n')).toContain('Failed:   1 secret(s)');
    expect(readBackendConfig()).toBe('vault');
    // Vault holds nothing. Before the fix this read was answered
    // { 'secret/STRIPE_KEY': 'held-by-keychain' } from the cache.
    expect(vault).toEqual({});
    expect(await createBackend('vault').resolve('secret')).toEqual({});
  });

  it('after a migration that stops on an error, with nothing still being copied', async () => {
    writeBackendConfig('keychain');
    await readThroughConfiguredKeychain({ STRIPE_KEY: 'held-by-keychain' });
    vault = { STRIPE_KEY: 'held-by-vault' };
    vaultFailsMcpRead = true;

    expect(await runMigrate(['--from', 'vault', '--to', 'local'])).toBe(1);

    expect(err.join('\n')).toContain('Vault: read failed (HTTP 500)');
    expect(readBackendConfig()).toBe('keychain');
    // The prefix before the failing one was copied in full before the command
    // returned. Copied side by side, it was still being written at this point,
    // through the destination's cache layer when it has one.
    expect(await fileStore()).toEqual({ 'secret/STRIPE_KEY': 'held-by-vault' });
    expect(fs.existsSync(cacheFile())).toBe(false);
  });

  it('after a migration that found nothing to copy', async () => {
    writeBackendConfig('keychain');
    await readThroughConfiguredKeychain({ STRIPE_KEY: 'held-by-keychain' });

    expect(await runMigrate(['--from', 'vault', '--to', 'local'])).toBe(0);

    expect(out.join('\n')).toContain('No secrets found to migrate.');
    expect(readBackendConfig()).toBe('keychain');
    expect(fs.existsSync(cacheFile())).toBe(false);
  });
});

describe('the way out of an unreachable backend, and the destination of a migration (#372)', () => {
  it('offers a migration command that runs, not `backend migrate`', async () => {
    writeBackendConfig('1password');
    const refusal = (() => {
      try {
        createBackend('1password');
        return undefined;
      } catch (e) {
        return e as Error;
      }
    })();

    // Before the fix: `secretless-ai backend migrate --from 1password --to
    // local`, which `backend` refuses as `Unknown backend command: migrate`.
    const offered = /^ {4}secretless-ai (.+)$/m.exec(refusal?.message ?? '')?.[1];
    expect(offered).toBe('migrate --from 1password --to local');
    expect(await runBackend(offered!.split(' '))).toBe(2);
    // The command it names is `migrate` itself, which gets as far as the
    // source: it is not refused as a command line.
    await expect(runMigrate(offered!.split(' ').slice(1))).rejects.toThrow(
      /^Source backend "1password" is not reachable/,
    );
  });

  it('names an unreachable --to as the destination, without offering a migration', async () => {
    writeBackendConfig('local');

    const refusal = await runMigrate(['--from', 'local', '--to', '1password']).then(
      () => undefined,
      (e: Error) => e,
    );

    // Before the fix: 'Configured backend "1password" is not reachable', and
    // a migration away from it as the way out.
    expect(refusal?.message.split('\n')[0]).toBe(
      'Destination backend "1password" is not reachable: 1Password CLI (op) not found. Install from https://developer.1password.com/docs/cli',
    );
    expect(refusal?.message).toContain('Nothing was copied, and the configured backend is unchanged.');
    expect(refusal?.message).not.toContain('migrate --from');
    expect(readBackendConfig()).toBe('local');
  });

  it('refuses --from local --to keychain where, with no backend configured, both are the keychain', async () => {
    // A `secret-tool` stand-in, so a Linux runner sees a likely keychain as
    // macOS always does. Nothing here starts it.
    const bin = path.join(root, 'bin');
    fs.mkdirSync(bin);
    fs.writeFileSync(path.join(bin, 'secret-tool'), '#!/bin/sh\nexit 1\n', { mode: 0o755 });
    process.env.PATH = `${bin}${path.delimiter}${saved.PATH ?? ''}`;
    expect(readBackendConfig()).toBeUndefined();

    expect(await runMigrate(['--from', 'local', '--to', 'keychain'])).toBe(1);

    // Before the fix: the keychain was read and written as two stores, and
    // the keychain was then configured; here, with nothing in it, the
    // migration reported 'No secrets found to migrate.' and exited 0.
    expect(err.join('\n')).toMatch(
      /Source and destination are the same store: --from local and --to keychain are both (keychain-macos|keychain-linux|local) on this machine\./,
    );
    expect(err.join('\n')).toContain('secretless-ai backend set keychain');
    expect(out.join('\n')).not.toContain('Secretless Migration');
    expect(readBackendConfig()).toBeUndefined();
  });

  it('builds --to local as the encrypted file that `local` names once the migration configures it', () => {
    const bin = path.join(root, 'bin');
    fs.mkdirSync(bin);
    fs.writeFileSync(path.join(bin, 'secret-tool'), '#!/bin/sh\nexit 1\n', { mode: 0o755 });
    process.env.PATH = `${bin}${path.delimiter}${saved.PATH ?? ''}`;

    expect(createBackend('local', undefined, true, { role: 'destination' })).toBeInstanceOf(LocalBackend);
    // CONTROL: on a platform with a keychain, the unconfigured default for the
    // same type is the keychain, which a copy into left `local` empty.
    if (process.platform === 'darwin' || process.platform === 'linux') {
      expect(createBackend('local')).not.toBeInstanceOf(LocalBackend);
    }
  });

  it('reports a Vault that refuses the LIST, instead of migrating nothing at exit 0', async () => {
    writeBackendConfig('keychain');
    vault = { STRIPE_KEY: 'held-by-vault' };
    vaultListStatus = 400;

    expect(await runMigrate(['--from', 'vault', '--to', 'local'])).toBe(1);

    // Before the fix: 'No secrets found to migrate.' and exit 0.
    expect(err.join('\n')).toContain('Vault: list failed (HTTP 400)');
    expect(out.join('\n')).not.toContain('No secrets found to migrate.');
    expect(readBackendConfig()).toBe('keychain');
  });
});

describe('backend set removes the value cache (#372)', () => {
  it('so the new backend is not answered for from the previous one\'s entries', async () => {
    writeBackendConfig('keychain');
    await readThroughConfiguredKeychain({ STRIPE_KEY: 'held-by-keychain' });
    expect(fs.existsSync(cacheFile())).toBe(true);

    expect(await runBackend(['set', 'vault'])).toBe(0);

    expect(readBackendConfig()).toBe('vault');
    expect(fs.existsSync(cacheFile())).toBe(false);
    // Vault holds nothing. Before the fix this read was answered
    // { 'secret/STRIPE_KEY': 'held-by-keychain' } from the cache.
    expect(await createBackend('vault').resolve('secret')).toEqual({});
  });
});
