/**
 * `secret sync` copies named secrets from a shared backend into this machine's
 * store (#176). Before it, a machine using the local store had no way to pull
 * the names a project needs from the team's 1Password, Vault or GCP Secret
 * Manager, and `secret sync` was refused as an unknown option set.
 *
 * Every store here is a real `LocalBackend` with an explicit key in a temporary
 * directory, so no test reaches the OS keychain. The shared backend is a stand-in
 * that keeps entries in memory and records every write it is asked for.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { LocalBackend } from './backends/local';
import { createBackend } from './backends/factory';
import type { BackendHealth, SecretBackend } from './backends/types';
import { SecretStore } from './secret-store';
import { syncSecrets } from './secret-sync';
import { runSetup } from './setup';
import { runSecret, runSecretSync } from './commands/secrets';

/** A shared backend: entries in memory, every call recorded. */
class SharedBackend implements SecretBackend {
  readonly name: string;
  readonly writes: string[] = [];
  readonly reads: string[] = [];
  healthy = true;
  /** Answer a prefix listing with nothing, as a token without `list` does. */
  canList = true;
  /** Names whose read raises. */
  readonly failing = new Set<string>();
  /** Answer a miss with every entry under the asked path, as GCP's fallback does. */
  listOnMiss = false;

  constructor(readonly entries: Record<string, string>, name = '1password') {
    this.name = name;
  }

  async resolve(key: string): Promise<Record<string, string>> {
    this.reads.push(key);
    const name = key.split('/').pop() ?? '';
    if (this.failing.has(name)) throw new Error(`permission denied reading "${key}"\nsecond line`);
    if (key in this.entries) return { [key]: this.entries[key] };
    const prefix = key + '/';
    const under = Object.keys(this.entries).filter((k) => k.startsWith(prefix));
    if (under.length > 0) {
      if (!this.canList) return {};
      return Object.fromEntries(under.map((k) => [k, this.entries[k]]));
    }
    if (this.listOnMiss) {
      return Object.fromEntries(Object.entries(this.entries).map(([k, v]) => [`${key}/${k.split('/').pop()}`, v]));
    }
    return {};
  }

  async healthCheck(): Promise<BackendHealth> {
    return this.healthy
      ? { healthy: true, latencyMs: 0 }
      : { healthy: false, latencyMs: 0, message: '1Password CLI not authenticated.\nRun `op signin`.' };
  }

  // Never called by sync. Present so a write would be recorded, not crash.
  async store(key: string): Promise<void> { this.writes.push(`store ${key}`); }
  async delete(key: string): Promise<boolean> { this.writes.push(`delete ${key}`); return false; }
}

const VALUES = {
  API_KEY: 'FAKE-shared-api-value-0001',
  DATABASE_URL: 'postgres://shared-db-value-0002',
  STRIPE_KEY: 'FAKE_shared_stripe_value_0003',
};

function shared(): SharedBackend {
  return new SharedBackend({
    'secret/API_KEY': VALUES.API_KEY,
    'secret/DATABASE_URL': VALUES.DATABASE_URL,
    'secret/STRIPE_KEY': VALUES.STRIPE_KEY,
  });
}

let tmp: string;
let projectDir: string;
let backend: LocalBackend;
let store: SecretStore;
let out: string[];
let logSpy: ReturnType<typeof vi.spyOn>;
let errSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sls-sync-'));
  projectDir = path.join(tmp, 'project');
  fs.mkdirSync(projectDir);
  backend = new LocalBackend({ storeDir: path.join(tmp, 'store'), key: 'test-key' });
  store = new SecretStore({ backend });
  out = [];
  const capture = (...a: unknown[]): void => { out.push(a.map(String).join(' ')); };
  logSpy = vi.spyOn(console, 'log').mockImplementation(capture);
  errSpy = vi.spyOn(console, 'error').mockImplementation(capture);
});

afterEach(() => {
  logSpy.mockRestore();
  errSpy.mockRestore();
  fs.rmSync(tmp, { recursive: true, force: true });
});

async function localSnapshot(): Promise<Record<string, string>> {
  return backend.resolve('secret');
}

function sync(args: string[], source: SecretBackend): Promise<number> {
  return runSecretSync(args, { store, createSource: () => source, cwd: projectDir });
}

function printed(): string {
  return out.join('\n');
}

describe('secret sync seeds an empty store from a shared backend (#176)', () => {
  it('after `sync --manifest .secretless`, `setup --check` reports no missing names', async () => {
    fs.writeFileSync(path.join(projectDir, '.secretless'), 'API_KEY\nDATABASE_URL\nSTRIPE_KEY  optional\n');
    const before = await runSetup(projectDir, { backend, check: true });
    expect(before.missingNames).toEqual(['API_KEY', 'DATABASE_URL']);

    const source = shared();
    const code = await sync(['--from', '1password', '--manifest', '.secretless'], source);

    expect(code).toBe(0);
    const after = await runSetup(projectDir, { backend, check: true });
    expect(after.complete).toBe(true);
    expect(after.missingNames).toEqual([]);
    expect(await store.getSecret('API_KEY')).toBe(VALUES.API_KEY);
    expect(await store.getSecret('DATABASE_URL')).toBe(VALUES.DATABASE_URL);
    // Required names only: the optional one is not copied.
    expect(await store.getSecret('STRIPE_KEY')).toBeUndefined();
    expect(source.writes).toEqual([]);
    expect(printed()).toMatch(/created\s+API_KEY/);
    expect(printed()).toContain('Verify:  npx secretless-ai setup --check');
  });

  it('defaults to the required names of ./.secretless', async () => {
    fs.writeFileSync(path.join(projectDir, '.secretless'), 'API_KEY\n');
    expect(await sync(['--from', '1password'], shared())).toBe(0);
    expect(Object.keys(await localSnapshot())).toEqual(['secret/API_KEY']);
  });

  it('copies exactly the names given with --only', async () => {
    expect(await sync(['--from', '1password', '--only', 'STRIPE_KEY,API_KEY'], shared())).toBe(0);
    expect(Object.keys(await localSnapshot()).sort()).toEqual(['secret/API_KEY', 'secret/STRIPE_KEY']);
  });

  it('is reached from `secret sync`, which used to be an unknown subcommand', async () => {
    // The default dependencies build real backends, so stop at the first usage
    // check: the point is only that `sync` dispatches to the sync handler.
    expect(await runSecret(['sync'])).toBe(2);
    expect(printed()).toContain('--from is required');
    expect(printed()).not.toContain('Unknown secret command');
  });
});

describe('secret sync --dry-run never changes the local store', () => {
  it('reports would-create, would-update and conflict, and writes nothing', async () => {
    await store.setSecret('API_KEY', VALUES.API_KEY);
    await store.setSecret('DATABASE_URL', 'postgres://local-db-value');
    const before = await localSnapshot();

    for (const force of [false, true]) {
      out.length = 0;
      const args = ['--from', '1password', '--only', 'API_KEY,DATABASE_URL,STRIPE_KEY', '--dry-run'];
      const code = await sync(force ? [...args, '--force'] : args, shared());
      expect(await localSnapshot()).toEqual(before);
      expect(printed()).toContain('Dry run: nothing is written.');
      expect(printed()).toMatch(/would create\s+STRIPE_KEY/);
      expect(printed()).toMatch(/unchanged\s+API_KEY/);
      if (force) {
        expect(printed()).toMatch(/would update\s+DATABASE_URL/);
        expect(code).toBe(0);
      } else {
        expect(printed()).toMatch(/conflict\s+DATABASE_URL/);
        // The exit code the real run would have.
        expect(code).toBe(1);
      }
      expect(printed()).toContain('Apply:   npx secretless-ai secret sync --from 1password --only API_KEY,DATABASE_URL,STRIPE_KEY');
    }
  });
});

describe('secret sync does not overwrite a local value without --force', () => {
  it('leaves a differing value, names the conflict, and exits 1', async () => {
    await store.setSecret('API_KEY', 'local-value');
    const code = await sync(['--from', '1password', '--only', 'API_KEY,DATABASE_URL'], shared());
    expect(code).toBe(1);
    expect(await store.getSecret('API_KEY')).toBe('local-value');
    expect(await store.getSecret('DATABASE_URL')).toBe(VALUES.DATABASE_URL);
    expect(printed()).toMatch(/conflict\s+API_KEY/);
    expect(printed()).toContain('Fix:     npx secretless-ai secret sync --from 1password --only API_KEY --force');
  });

  it('replaces it with --force', async () => {
    await store.setSecret('API_KEY', 'local-value');
    expect(await sync(['--from', '1password', '--only', 'API_KEY', '--force'], shared())).toBe(0);
    expect(await store.getSecret('API_KEY')).toBe(VALUES.API_KEY);
    expect(printed()).toMatch(/updated\s+API_KEY/);
  });
});

describe('secret sync never prints a value', () => {
  it('keeps every value out of the output on every path', async () => {
    await store.setSecret('API_KEY', 'local-value-should-not-print');
    const source = shared();
    source.failing.add('STRIPE_KEY');
    await sync(['--from', '1password', '--only', 'API_KEY,DATABASE_URL,STRIPE_KEY,ABSENT', '--dry-run'], source);
    await sync(['--from', '1password', '--only', 'API_KEY,DATABASE_URL,STRIPE_KEY,ABSENT'], source);
    await sync(['--from', '1password', '--only', 'API_KEY', '--force'], source);
    const text = printed();
    for (const value of [...Object.values(VALUES), 'local-value-should-not-print']) {
      expect(text).not.toContain(value);
    }
  });
});

describe('secret sync reports what it could not copy', () => {
  it('a name in neither store fails the run and is named; a local-only name is kept', async () => {
    await store.setSecret('LOCAL_ONLY', 'v');
    const code = await sync(['--from', '1password', '--only', 'API_KEY,LOCAL_ONLY,ABSENT'], shared());
    expect(code).toBe(1);
    expect(printed()).toMatch(/not found\s+ABSENT\s+not in 1password, and not stored on this machine/);
    expect(printed()).toMatch(/kept\s+LOCAL_ONLY/);
    expect(printed()).toContain('Fix:     npx secretless-ai secret set ABSENT');
    expect(await store.getSecret('LOCAL_ONLY')).toBe('v');
  });

  it('a read error fails that name only, with its first line', async () => {
    const source = shared();
    source.failing.add('DATABASE_URL');
    const code = await sync(['--from', '1password', '--only', 'API_KEY,DATABASE_URL'], source);
    expect(code).toBe(1);
    expect(printed()).toMatch(/failed\s+DATABASE_URL\s+could not read it from 1password: permission denied reading "secret\/DATABASE_URL"$/m);
    expect(printed()).not.toContain('second line');
    expect(await store.getSecret('API_KEY')).toBe(VALUES.API_KEY);
  });

  it('an unreachable source stops before any entry is read, and nothing is written', async () => {
    const source = shared();
    source.healthy = false;
    const code = await sync(['--from', '1password', '--only', 'API_KEY'], source);
    expect(code).toBe(1);
    expect(source.reads).toEqual([]);
    expect(await localSnapshot()).toEqual({});
    expect(printed()).toContain('Source backend "1password" is not reachable: 1Password CLI not authenticated. Run `op signin`.');
    expect(printed()).toContain('Verify:  op account get');
  });
});

describe('secret sync prints its errors in the layout the other secret commands use (#233)', () => {
  function stderr(): string {
    return errSpy.mock.calls.map((call: unknown[]) => call.map(String).join(' ')).join('\n');
  }

  it('an unreachable source: a blank line, Error:, the message, its Verify line, a blank line', async () => {
    const source = shared();
    source.healthy = false;
    expect(await sync(['--from', '1password', '--only', 'API_KEY'], source)).toBe(1);
    expect(stderr()).toBe([
      '',
      '  Error: Source backend "1password" is not reachable: 1Password CLI not authenticated. Run `op signin`.',
      '',
      '  Nothing was read from it, and nothing on this machine was changed.',
      '',
      '  Verify:  op account get',
      '',
    ].join('\n'));
  });

  it('a source that cannot be opened: every line of the message indented, none at column 0', async () => {
    const code = await runSecretSync(['--from', '1password', '--only', 'API_KEY'], {
      store,
      cwd: projectDir,
      createSource: () => {
        throw new Error('op is not installed\nInstall it, then run the sync again.');
      },
    });
    expect(code).toBe(1);
    expect(stderr()).toBe([
      '',
      '  Error: op is not installed',
      '  Install it, then run the sync again.',
      '',
    ].join('\n'));
    expect(await localSnapshot()).toEqual({});
  });
});

describe('secret sync reads by name, so a source that cannot list still syncs', () => {
  it('copies every requested name from a backend whose prefix listing returns nothing', async () => {
    const source = shared();
    source.canList = false;
    expect(await source.resolve('secret')).toEqual({});
    source.reads.length = 0;

    const result = await syncSecrets(source, store, ['API_KEY', 'DATABASE_URL']);
    expect(result.ok).toBe(true);
    expect(result.entries.map((e) => e.action)).toEqual(['create', 'create']);
    expect(source.reads).toEqual(['secret/API_KEY', 'secret/DATABASE_URL']);
  });

  it('takes the exact key only when a miss is answered with other entries', async () => {
    const source = shared();
    source.listOnMiss = true;
    const result = await syncSecrets(source, store, ['ABSENT']);
    expect(result.entries).toEqual([{ name: 'ABSENT', action: 'not-found' }]);
    expect(await localSnapshot()).toEqual({});
  });
});

describe('secret sync usage', () => {
  it('refuses --only with --manifest, a missing --from, an unknown backend and a bad name', async () => {
    expect(await sync(['--from', '1password', '--only', 'A', '--manifest', '.secretless'], shared())).toBe(2);
    expect(await sync(['--only', 'A'], shared())).toBe(2);
    expect(await sync(['--from', 'dropbox', '--only', 'A'], shared())).toBe(2);
    expect(await sync(['--from', '1password', '--only', 'not a name'], shared())).toBe(2);
    expect(await localSnapshot()).toEqual({});
  });

  it('refuses a source that is this machine\'s own store', async () => {
    const code = await sync(['--from', 'local', '--only', 'API_KEY'], new SharedBackend({}, 'local'));
    expect(code).toBe(2);
    expect(printed()).toContain("is this machine's own store (local)");
  });

  it('without --only or a manifest, says how to choose names and reads nothing', async () => {
    const source = shared();
    expect(await sync(['--from', '1password'], source)).toBe(2);
    expect(source.reads).toEqual([]);
    expect(printed()).toContain('No .secretless manifest in this directory');
  });

  it('refuses an unparseable manifest without reading the source', async () => {
    fs.writeFileSync(path.join(projectDir, '.secretless'), 'required:\n  - API_KEY\n');
    const source = shared();
    expect(await sync(['--from', '1password'], source)).toBe(1);
    expect(source.reads).toEqual([]);
  });

  it('refuses a sync-only flag on another subcommand rather than ignoring it', async () => {
    // `secret set --dry-run` would otherwise store the value it was asked to preview.
    expect(await runSecret(['set', '--dry-run', 'API_KEY=x'])).toBe(2);
    expect(printed()).toContain('--dry-run applies to `secret sync` and `secret push` only');
  });
});

describe("createBackend's source role", () => {
  const saved = { HOME: process.env.HOME, VAULT_ADDR: process.env.VAULT_ADDR, VAULT_TOKEN: process.env.VAULT_TOKEN };

  afterEach(() => {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  });

  it('a sync source is not cached under names this machine\'s store also reads', () => {
    // The cache file is keyed by entry name alone, so a source value cached
    // there would later be served as the local value for the same name.
    process.env.HOME = tmp;
    process.env.VAULT_ADDR = 'http://127.0.0.1:1';
    process.env.VAULT_TOKEN = 'test-token-not-real';
    expect(createBackend('vault').name).toBe('cached(vault)');
    expect(createBackend('vault', undefined, true, { role: 'source' }).name).toBe('vault');
  });

  it('an unreachable source is named as the source, with no migration offered', () => {
    delete process.env.VAULT_ADDR;
    delete process.env.VAULT_TOKEN;
    expect(() => createBackend('vault', undefined, true, { role: 'source' })).toThrow(
      /^Source backend "vault" is not reachable: VAULT_ADDR and VAULT_TOKEN must be set\n/,
    );
    try {
      createBackend('vault', undefined, true, { role: 'source' });
    } catch (err) {
      expect((err as Error).message).toContain('Verify:  vault token lookup');
      expect((err as Error).message).not.toContain('migrate');
    }
    // The configured role keeps its message.
    expect(() => createBackend('vault')).toThrow(/^Configured backend "vault" is not reachable/);
  });
});
