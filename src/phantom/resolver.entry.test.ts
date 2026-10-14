import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { resolveRef, RefResolutionError } from './resolver';

/**
 * #383: `secret://vault/NAME` resolved to the value of a different entry when
 * NAME was not stored but an entry under `secret/NAME/` was. Vault answered the
 * 404 on `secret/NAME` by listing it as a prefix, and the resolver took the
 * first entry of that listing as the reference's value.
 *
 * These run the real factory and the real Vault backend under a home of their
 * own, against a KV v2 server played by a fetch stand-in that answers LIST.
 */
describe('resolveRef: a vault reference is answered by its own entry only (#383)', () => {
  const saved = {
    HOME: process.env.HOME,
    VAULT_ADDR: process.env.VAULT_ADDR,
    VAULT_TOKEN: process.env.VAULT_TOKEN,
  };
  let root: string;
  let vault: Record<string, string>;
  let vaultRequests: ReturnType<typeof vaultServer>;

  /**
   * A Vault KV v2 server on mount `secret` holding each store key in `vault`
   * (store key `secret/DB/replica` at Vault path `secret/data/secret/DB/replica`),
   * with a token that may read and list.
   */
  function vaultServer() {
    const json = (status: number, body: unknown) => ({ ok: status < 300, status, json: async () => body });
    return vi.fn(async (url: string, init: { method: string }) => {
      const { pathname } = new URL(url);
      const read = /^\/v1\/secret\/data\/(.+)$/.exec(pathname)?.[1];
      if (read !== undefined && init.method === 'GET' && read in vault) {
        return json(200, { data: { data: { value: vault[read] } } });
      }
      const listed = /^\/v1\/secret\/metadata\/(.+)$/.exec(pathname)?.[1];
      if (listed !== undefined && init.method === 'LIST') {
        const keys = Object.keys(vault)
          .filter((k) => k.startsWith(`${listed}/`))
          .map((k) => k.slice(listed.length + 1));
        if (keys.length > 0) return json(200, { data: { keys } });
      }
      return json(404, { errors: [] });
    });
  }

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-resolver-entry-test-'));
    const home = path.join(root, 'home');
    fs.mkdirSync(home);
    process.env.HOME = home;
    process.env.VAULT_ADDR = 'http://127.0.0.1:1';
    process.env.VAULT_TOKEN = 'not-a-real-token';
    vault = {};
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

  it('fails a name Vault does not hold, not answering it with an entry stored under that name', async () => {
    vault = { 'secret/DB/replica': 'value-of-the-replica-entry' };

    const refusal = await resolveRef('secret://vault/DB').then(
      (r) => r,
      (e: Error) => e,
    );

    // Before the fix this resolved to 'value-of-the-replica-entry'.
    expect(refusal).toBeInstanceOf(RefResolutionError);
    expect((refusal as RefResolutionError).message).toBe('Secret not found: secret://vault/DB');
    // One exact read: the name is not listed as a prefix.
    expect(vaultRequests.mock.calls.map(([url, init]) => [init.method, new URL(url).pathname])).toEqual([
      ['GET', '/v1/secret/data/secret/DB'],
    ]);
  });

  it('answers a name Vault holds with its own value beside an entry stored under it', async () => {
    vault = { 'secret/DB': 'value-of-the-db-entry', 'secret/DB/replica': 'value-of-the-replica-entry' };

    expect((await resolveRef('secret://vault/DB')).value).toBe('value-of-the-db-entry');
    expect((await resolveRef('secret://vault/DB/replica')).value).toBe('value-of-the-replica-entry');
  });
});
