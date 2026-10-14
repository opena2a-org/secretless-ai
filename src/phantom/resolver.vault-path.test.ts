import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { resolveRef } from './resolver';

/**
 * #384: the path of a `secret://vault/` reference was placed in the request
 * URL as it was, and the URL resolved its ".." segments.
 * `secret://vault/../../../sys/policies/acl` sent `GET /v1/sys/policies/acl`
 * with the Vault token. The real factory and Vault backend, with fetch
 * recorded and every request answered 404.
 */
describe('resolveRef: a secret://vault/ path stays inside the KV mount (#384)', () => {
  const saved = {
    HOME: process.env.HOME,
    VAULT_ADDR: process.env.VAULT_ADDR,
    VAULT_TOKEN: process.env.VAULT_TOKEN,
  };
  const fetchMock = vi.fn();
  let root: string;

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-resolver-vault-path-test-'));
    fs.mkdirSync(path.join(root, 'home'));
    process.env.HOME = path.join(root, 'home');
    process.env.VAULT_ADDR = 'http://127.0.0.1:8200';
    process.env.VAULT_TOKEN = 'FAKE-TOKEN-1234';
    fetchMock.mockReset();
    fetchMock.mockResolvedValue({ ok: false, status: 404 });
    vi.stubGlobal('fetch', fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    fs.rmSync(root, { recursive: true, force: true });
  });

  const requested = (): string[] =>
    fetchMock.mock.calls.map(([url, init]) => `${init.method} ${new URL(url).pathname}`);

  it('a path with ".." segments sends no request', async () => {
    const uri = 'secret://vault/../../../sys/policies/acl';

    await expect(resolveRef(uri)).rejects.toThrow(`Secret not found: ${uri}`);

    // Before the fix: ['GET /v1/sys/policies/acl'].
    expect(requested()).toEqual([]);
  });

  it('a path with "%2e%2e" segments is read under the mount, as the name it is', async () => {
    const uri = 'secret://vault/%2e%2e/%2e%2e/%2e%2e/sys/policies/acl';

    await expect(resolveRef(uri)).rejects.toThrow(`Secret not found: ${uri}`);

    // resolveRef reads the reference as an exact key (#383), so no LIST follows.
    expect(requested()).toEqual([
      'GET /v1/secret/data/secret/%252e%252e/%252e%252e/%252e%252e/sys/policies/acl',
    ]);
  });
});
