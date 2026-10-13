/**
 * Reading one secret name from Vault does not list it as a prefix (#375).
 *
 * The Vault stubbed here answers a GET of a name it holds with the value, a
 * GET of any other name with 404, and every LIST with 403: a token that may
 * read `secret/data/*` and may not list `secret/metadata/*`.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { VaultBackend } from './backends/vault';
import { CachedBackend } from './backends/cache';
import { LocalBackend } from './backends/local';
import type { WritableSecretBackend } from './backends/types';
import { SecretStore } from './secret-store';
import { syncSecrets } from './secret-sync';
import { runSecret } from './commands/secrets';
import { CredentialResolver } from './broker/resolver';
import { McpVault } from './mcp/vault';

const ADDR = 'http://127.0.0.1:8200';
const DATA = 'secret/data/secret/';
const STORED_VALUE = 'stored-value-1234';
const ENV_NAME = 'VAULT_READ_WITHOUT_LIST_TEST';

let dir: string;
/** What the stubbed Vault holds under `secret/`, by name. */
let held: Map<string, string>;
/** Every request the stub answered, as `METHOD path`. */
let requests: string[];

function vault(): VaultBackend {
  return new VaultBackend({ addr: ADDR, token: 'not-a-real-token' });
}

/** Vault behind the value cache, the layer the backend factory puts over it while the cache TTL is above zero. */
function cachedVault(): CachedBackend {
  return new CachedBackend(vault(), { storeDir: path.join(dir, 'cache') });
}

function listRequests(): string[] {
  return requests.filter((r) => r.startsWith('LIST '));
}

async function capture(run: () => Promise<number>): Promise<{ code: number; out: string; err: string }> {
  const out: string[] = [];
  const err: string[] = [];
  const log = vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { out.push(a.join(' ')); });
  const error = vi.spyOn(console, 'error').mockImplementation((...a: unknown[]) => { err.push(a.join(' ')); });
  try {
    return { code: await run(), out: out.join('\n'), err: err.join('\n') };
  } finally {
    log.mockRestore();
    error.mockRestore();
  }
}

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-vault-nolist-'));
  held = new Map([['STORED_NAME', STORED_VALUE]]);
  requests = [];
  vi.stubGlobal('fetch', vi.fn(async (url: string, init: RequestInit) => {
    const method = init.method ?? 'GET';
    const route = String(url).slice(`${ADDR}/v1/`.length);
    requests.push(`${method} ${route}`);
    if (route === 'sys/health') return { ok: true, status: 200 };
    if (method === 'LIST') return { ok: false, status: 403 };
    if (!route.startsWith(DATA)) return { ok: false, status: 404 };
    const name = route.slice(DATA.length);
    if (method === 'POST') {
      held.set(name, (JSON.parse(String(init.body)) as { data: { value: string } }).data.value);
      return { ok: true, status: 200, json: async () => ({ data: { version: 1 } }) };
    }
    const value = held.get(name);
    if (value === undefined) return { ok: false, status: 404 };
    return { ok: true, status: 200, json: async () => ({ data: { data: { value } } }) };
  }));
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
  fs.rmSync(dir, { recursive: true, force: true });
});

describe.each<[string, () => WritableSecretBackend]>([
  ['the Vault backend', vault],
  ['the Vault backend behind the value cache', cachedVault],
])('a Vault token that may read and may not list: %s', (_label, backend) => {
  it('getSecret of a name that is not stored answers undefined and sends no LIST', async () => {
    const store = new SecretStore({ backend: backend() });

    await expect(store.getSecret('MISSING_NAME')).resolves.toBeUndefined();
    expect(requests).toEqual([`GET ${DATA}MISSING_NAME`]);
  });

  it('CONTROL: getSecret of a stored name answers its value', async () => {
    const store = new SecretStore({ backend: backend() });

    await expect(store.getSecret('STORED_NAME')).resolves.toBe(STORED_VALUE);
    expect(listRequests()).toEqual([]);
  });

  it('CONTROL: listing the store still reports the refused LIST', async () => {
    const store = new SecretStore({ backend: backend() });

    await expect(store.listSecrets()).rejects.toThrow('Vault: permission denied listing "secret"');
    expect(listRequests()).toEqual(['LIST secret/metadata/secret']);
  });

  it('secret show of a name that is not stored says so, and --json answers stored: false', async () => {
    const createStore = () => new SecretStore({ backend: backend() });

    const plain = await capture(() => runSecret(['show', 'MISSING_NAME'], { createStore }));
    expect(plain.code).toBe(1);
    expect(plain.err).toContain('Secret not found: MISSING_NAME');
    expect(plain.err).not.toContain('permission denied');

    const json = await capture(() => runSecret(['show', 'MISSING_NAME', '--json'], { json: true, createStore }));
    expect(json.code).toBe(1);
    expect(JSON.parse(json.out)).toMatchObject({ name: 'MISSING_NAME', stored: false, backend: 'vault' });
    expect(listRequests()).toEqual([]);
  });

  it('the broker lookup of a name that is not stored reaches its environment-variable fallback', async () => {
    vi.stubEnv(ENV_NAME, 'from-the-environment');
    const resolver = new CredentialResolver({
      secretStore: new SecretStore({ backend: backend() }),
      mcpVault: new McpVault({ backend: new LocalBackend({ storeDir: path.join(dir, 'mcp'), key: 'test-key' }) }),
    });

    await expect(resolver.resolve(ENV_NAME)).resolves.toBe('from-the-environment');
    expect(requests).toEqual([`GET ${DATA}${ENV_NAME}`]);
  });
});

describe('a Vault token that may read and may not list: the other reads of one name', () => {
  it('setSecret stores a name whose exposure is open and whose value Vault no longer holds', async () => {
    const store = new SecretStore({ backend: vault() });
    await store.recordExposure('STORED_NAME', 'a shared log', new Date());
    held.delete('STORED_NAME');
    requests = [];

    const { rotation } = await store.setSecret('STORED_NAME', 'rotated-value-5678');

    expect(rotation.kind).toBe('closed');
    expect(held.get('STORED_NAME')).toBe('rotated-value-5678');
    expect(requests).toEqual([`GET ${DATA}STORED_NAME`, `POST ${DATA}STORED_NAME`]);
  });

  it('secret sync reports a name Vault does not hold as not found, and copies the one it holds', async () => {
    const local = new SecretStore({ backend: new LocalBackend({ storeDir: path.join(dir, 'local'), key: 'test-key' }) });

    const result = await syncSecrets(vault(), local, ['STORED_NAME', 'MISSING_NAME']);

    expect(result.entries).toEqual([
      { name: 'STORED_NAME', action: 'create' },
      { name: 'MISSING_NAME', action: 'not-found' },
    ]);
    await expect(local.getSecret('STORED_NAME')).resolves.toBe(STORED_VALUE);
    expect(listRequests()).toEqual([]);
  });
});
