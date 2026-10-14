import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { VaultBackend } from './vault';

const mockFetch = vi.fn();

beforeEach(() => {
  vi.stubGlobal('fetch', mockFetch);
  mockFetch.mockReset();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

const TEST_ADDR = 'http://127.0.0.1:8200';
const TEST_TOKEN = 'hvs.test-token-123';

function createVault(overrides?: { addr?: string; token?: string; mountPath?: string }) {
  return new VaultBackend({
    addr: overrides?.addr ?? TEST_ADDR,
    token: overrides?.token ?? TEST_TOKEN,
    mountPath: overrides?.mountPath,
  });
}

describe('VaultBackend', () => {
  describe('resolve', () => {
    it('reads a KV v2 secret and returns { path: value }', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          data: {
            data: { value: 'secret-value-123' },
            metadata: { version: 1 },
          },
        }),
      });

      const vault = createVault();
      const result = await vault.resolve('secret/MY_KEY');

      expect(result).toEqual({ 'secret/MY_KEY': 'secret-value-123' });
      expect(mockFetch).toHaveBeenCalledTimes(1);

      const [url, opts] = mockFetch.mock.calls[0];
      expect(url).toBe(`${TEST_ADDR}/v1/secret/data/secret/MY_KEY`);
      expect(opts.method).toBe('GET');
      expect(opts.headers['X-Vault-Token']).toBe(TEST_TOKEN);
    });

    it('lists and reads keys when direct read returns 404 (prefix mode)', async () => {
      // Direct read of "secret" path -> 404
      mockFetch.mockResolvedValueOnce({ ok: false, status: 404 });

      // LIST metadata -> returns two keys
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ data: { keys: ['KEY_A', 'KEY_B'] } }),
      });

      // Read KEY_A
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ data: { data: { value: 'val-a' } } }),
      });

      // Read KEY_B
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ data: { data: { value: 'val-b' } } }),
      });

      const vault = createVault();
      const result = await vault.resolve('secret');

      expect(result).toEqual({
        'secret/KEY_A': 'val-a',
        'secret/KEY_B': 'val-b',
      });
      expect(mockFetch).toHaveBeenCalledTimes(4);
    });

    it('skips subdirectories in LIST results', async () => {
      mockFetch.mockResolvedValueOnce({ ok: false, status: 404 });
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ data: { keys: ['KEY_A', 'subdir/'] } }),
      });
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ data: { data: { value: 'val-a' } } }),
      });

      const vault = createVault();
      const result = await vault.resolve('secret');

      expect(result).toEqual({ 'secret/KEY_A': 'val-a' });
    });

    it('returns empty for 404 on both read and list', async () => {
      mockFetch.mockResolvedValueOnce({ ok: false, status: 404 });
      mockFetch.mockResolvedValueOnce({ ok: false, status: 404 });

      const vault = createVault();
      const result = await vault.resolve('nonexistent');
      expect(result).toEqual({});
    });

    // #372: only a 404 means nothing is stored under the prefix. A refused
    // LIST was answered as an empty store, while a refused GET throws.
    it.each([
      [400, 'Vault: list failed (HTTP 400)'],
      [405, 'Vault: list failed (HTTP 405)'],
      [500, 'Vault: list failed (HTTP 500)'],
      [403, 'Vault: permission denied listing "secret"'],
    ])('throws when the LIST of a prefix is answered %i', async (status, message) => {
      mockFetch.mockResolvedValueOnce({ ok: false, status: 404 });
      mockFetch.mockResolvedValueOnce({ ok: false, status });

      const vault = createVault();
      await expect(vault.resolve('secret')).rejects.toThrow(message);
      expect(mockFetch.mock.calls[1][1].method).toBe('LIST');
    });

    // #375: an exact read asks for one entry. Its 404 was followed by a LIST
    // of the same path as a prefix, and a refused LIST threw.
    it('an exact read answered 404 returns nothing and sends no LIST', async () => {
      mockFetch.mockResolvedValueOnce({ ok: false, status: 404 });
      mockFetch.mockResolvedValueOnce({ ok: false, status: 403 });

      const vault = createVault();
      await expect(vault.resolve('secret/MISSING_NAME', { exact: true })).resolves.toEqual({});
      expect(mockFetch).toHaveBeenCalledTimes(1);
      expect(mockFetch.mock.calls[0][1].method).toBe('GET');
    });

    it('an exact read answered 403 throws, as a read without the option does', async () => {
      mockFetch.mockResolvedValueOnce({ ok: false, status: 403 });

      const vault = createVault();
      await expect(vault.resolve('secret/MY_KEY', { exact: true }))
        .rejects.toThrow('Vault: permission denied reading "secret/MY_KEY"');
    });

    it('throws on 403', async () => {
      mockFetch.mockResolvedValueOnce({ ok: false, status: 403 });

      const vault = createVault();
      await expect(vault.resolve('forbidden')).rejects.toThrow('permission denied');
    });

    it('uses custom mount path', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ data: { data: { value: 'test' } } }),
      });

      const vault = createVault({ mountPath: 'custom-kv' });
      await vault.resolve('my-key');

      const [url] = mockFetch.mock.calls[0];
      expect(url).toBe(`${TEST_ADDR}/v1/custom-kv/data/my-key`);
    });
  });

  describe('store', () => {
    it('writes a KV v2 secret', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({}),
      });

      const vault = createVault();
      await vault.store('new-secret', 'my-value');

      expect(mockFetch).toHaveBeenCalledTimes(1);
      const [url, opts] = mockFetch.mock.calls[0];
      expect(url).toBe(`${TEST_ADDR}/v1/secret/data/new-secret`);
      expect(opts.method).toBe('POST');
      expect(JSON.parse(opts.body)).toEqual({ data: { value: 'my-value' } });
    });

    it('throws on 403', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 403,
      });

      const vault = createVault();
      await expect(vault.store('forbidden', 'value')).rejects.toThrow('permission denied');
    });
  });

  describe('delete', () => {
    it('deletes a KV v2 secret', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 204,
      });

      const vault = createVault();
      const result = await vault.delete('old-secret');
      expect(result).toBe(true);
    });

    it('returns false for 404', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
      });

      const vault = createVault();
      const result = await vault.delete('nonexistent');
      expect(result).toBe(false);
    });

    it('throws on 403', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 403,
      });

      const vault = createVault();
      await expect(vault.delete('forbidden')).rejects.toThrow('permission denied');
    });
  });

  describe('healthCheck', () => {
    it('returns healthy for 200', async () => {
      mockFetch.mockResolvedValueOnce({
        status: 200,
        ok: true,
      });

      const vault = createVault();
      const health = await vault.healthCheck();

      expect(health.healthy).toBe(true);
      expect(health.message).toBe('Vault is healthy');
      expect(health.latencyMs).toBeGreaterThanOrEqual(0);
    });

    it('returns healthy for standby (429)', async () => {
      mockFetch.mockResolvedValueOnce({
        status: 429,
        ok: false,
      });

      const vault = createVault();
      const health = await vault.healthCheck();

      expect(health.healthy).toBe(true);
      expect(health.message).toContain('standby');
    });

    it('returns unhealthy for sealed (503)', async () => {
      mockFetch.mockResolvedValueOnce({
        status: 503,
        ok: false,
      });

      const vault = createVault();
      const health = await vault.healthCheck();

      expect(health.healthy).toBe(false);
      expect(health.message).toBe('Vault is sealed');
    });

    it('returns unhealthy for not initialized (501)', async () => {
      mockFetch.mockResolvedValueOnce({
        status: 501,
        ok: false,
      });

      const vault = createVault();
      const health = await vault.healthCheck();

      expect(health.healthy).toBe(false);
      expect(health.message).toBe('Vault is not initialized');
    });

    it('returns unhealthy when connection fails', async () => {
      mockFetch.mockRejectedValueOnce(new Error('ECONNREFUSED'));

      const vault = createVault();
      const health = await vault.healthCheck();

      expect(health.healthy).toBe(false);
      expect(health.message).toBe('ECONNREFUSED');
    });

    it('returns unhealthy when VAULT_ADDR not set', async () => {
      const vault = new VaultBackend({ addr: '', token: TEST_TOKEN });
      const health = await vault.healthCheck();

      expect(health.healthy).toBe(false);
      expect(health.message).toContain('not configured');
    });
  });

  describe('configuration errors', () => {
    it('throws when VAULT_ADDR not set', async () => {
      const vault = new VaultBackend({ addr: '', token: TEST_TOKEN });
      await expect(vault.resolve('test')).rejects.toThrow('VAULT_ADDR is not set');
    });

    it('throws when VAULT_TOKEN not set', async () => {
      const vault = new VaultBackend({ addr: TEST_ADDR, token: '' });
      await expect(vault.resolve('test')).rejects.toThrow('VAULT_TOKEN is not set');
    });
  });
});

/**
 * #384: the key was placed in the request URL as it was, and the URL resolved
 * its dot segments, so `secret/../../../sys/policies/acl` was sent to
 * `/v1/sys/policies/acl` with the token.
 */
describe('VaultBackend: a key cannot move a request outside the KV mount (#384)', () => {
  const ESCAPE = 'secret/../../../sys/policies/acl';

  it('a key with a ".." segment is refused by every method, and no request is sent', async () => {
    const vault = createVault();
    const calls: Array<[string, () => Promise<unknown>]> = [
      ['resolve', () => vault.resolve(ESCAPE)],
      ['resolve exact', () => vault.resolve(ESCAPE, { exact: true })],
      ['store', () => vault.store(ESCAPE, 'value')],
      ['storeVersion', () => vault.storeVersion(ESCAPE, 'value')],
      ['hasEntry', () => vault.hasEntry(ESCAPE)],
      ['delete', () => vault.delete(ESCAPE)],
    ];
    for (const [name, call] of calls) {
      await expect(call(), name).rejects.toThrow(
        'Vault: refused the key "secret/../../../sys/policies/acl": a "." or ".." segment is resolved away '
        + 'in a request URL and can send the request outside the "secret" KV mount. The request was not sent.',
      );
    }
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('a key with a "." segment is refused, and no request is sent', async () => {
    await expect(createVault().resolve('secret/./MY_KEY')).rejects.toThrow('Vault: refused the key "secret/./MY_KEY"');
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('a listed name of ".." is refused before its read', async () => {
    mockFetch.mockResolvedValueOnce({ ok: false, status: 404 });
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({ data: { keys: ['..'] } }),
    });

    await expect(createVault().resolve('secret')).rejects.toThrow('Vault: refused the key "secret/.."');
    expect(mockFetch.mock.calls.map(([, opts]) => opts.method)).toEqual(['GET', 'LIST']);
  });

  // Forms the URL reads as dot segments or as the end of the path: "%2e" is
  // ".", "\" is "/", a tab or newline is dropped, "?" starts the query, "#"
  // the fragment. "%2f" is an escaped "/".
  const DISGUISED = [
    'secret/%2e%2e/%2E%2e/%2e./sys/policies/acl',
    'secret/..\\..\\..\\sys\\policies\\acl',
    'secret/.\t./.\n./.\r./sys/policies/acl',
    'secret/a%2f..%2f..%2f..%2fsys',
    'secret/KEY?list=true',
    'secret/KEY#fragment',
  ];

  for (const key of DISGUISED) {
    it(`${JSON.stringify(key)}: every request names that key under the mount`, async () => {
      mockFetch.mockResolvedValue({ ok: false, status: 404 });

      expect(await createVault().resolve(key)).toEqual({});

      const requests = mockFetch.mock.calls.map(([url, opts]) => ({ method: opts.method, url: new URL(url) }));
      expect(requests.map((r) => r.method)).toEqual(['GET', 'LIST']);
      const [read, list] = requests.map((r) => r.url);
      for (const url of [read, list]) {
        expect(url.origin).toBe(TEST_ADDR);
        expect(url.search).toBe('');
        expect(url.hash).toBe('');
      }
      expect(read.pathname.startsWith('/v1/secret/data/secret/')).toBe(true);
      expect(decodeURIComponent(read.pathname.slice('/v1/secret/data/'.length))).toBe(key);
      expect(list.pathname.startsWith('/v1/secret/metadata/secret/')).toBe(true);
      expect(decodeURIComponent(list.pathname.slice('/v1/secret/metadata/'.length))).toBe(key);
    });
  }

  it('a key of letters, digits, "_", "-" and "/" is sent as it is', async () => {
    mockFetch.mockResolvedValueOnce({ ok: true, status: 204 });

    await createVault({ mountPath: 'kv' }).delete('mcp/claude/github-server/GITHUB_TOKEN_2');

    expect(mockFetch.mock.calls[0][0]).toBe(`${TEST_ADDR}/v1/kv/data/mcp/claude/github-server/GITHUB_TOKEN_2`);
  });
});

describe('VaultBackend: every request is bounded end to end', () => {
  const VALUE = 'planted-vault-value-7c1e';

  /** A fetch that honours its abort signal and otherwise never settles. */
  const silentFetch = (_url: string, init: { signal: AbortSignal }) =>
    new Promise((_, reject) => {
      init.signal.addEventListener('abort', () => reject(new DOMException('This operation was aborted', 'AbortError')));
    });

  beforeEach(() => { vi.useFakeTimers(); });
  afterEach(() => { vi.useRealTimers(); });

  it('a read Vault never answers: throws within 10s, names the request, and says what to do', async () => {
    mockFetch.mockImplementationOnce(silentFetch);
    const outcome = createVault().resolve('secret/K').then(() => null, (e: Error) => e);
    await vi.advanceTimersByTimeAsync(10_000);
    const err = await outcome;
    expect(err).toBeInstanceOf(Error);
    expect(err!.message).toContain('Vault did not respond within 10s (GET /v1/secret/data/secret/K)');
    expect(err!.message).toContain(`Verify:  curl -s ${TEST_ADDR}/v1/sys/health`);
    expect(err!.message).toContain('Fix:');
    expect(err!.message).not.toContain('aborted');
  });

  it('a read whose body never arrives: the body read is under the same 10s bound', async () => {
    mockFetch.mockResolvedValueOnce({ ok: true, status: 200, json: () => new Promise(() => {}) });
    const outcome = createVault().resolve('secret/K').then(() => null, (e: Error) => e);
    await vi.advanceTimersByTimeAsync(10_000);
    const err = await outcome;
    expect(err).toBeInstanceOf(Error);
    expect(err!.message).toContain('Vault did not respond within 10s (GET /v1/secret/data/secret/K)');
  });

  it('a write Vault never answers: the error holds neither the token nor the value, nor userinfo in the address', async () => {
    mockFetch.mockImplementationOnce(silentFetch);
    const userinfo = ['ops', 'FAKE-pw-in-addr'].join(':');
    const vault = createVault({ addr: `http://${userinfo}@127.0.0.1:8200` });
    const outcome = vault.store('secret/K', VALUE).then(() => null, (e: Error) => e);
    await vi.advanceTimersByTimeAsync(10_000);
    const err = await outcome;
    expect(err!.message).toContain('Vault did not respond within 10s (POST /v1/secret/data/secret/K)');
    expect(err!.message).toContain('may still have been applied');
    for (const leaked of [VALUE, TEST_TOKEN, 'pw-in-addr', 'ops:']) {
      expect(err!.message).not.toContain(leaked);
    }
  });

  it('a health check Vault never answers: unhealthy within 5s, on one line, with a Verify command', async () => {
    mockFetch.mockImplementationOnce(silentFetch);
    const outcome = createVault().healthCheck();
    await vi.advanceTimersByTimeAsync(5_000);
    const health = await outcome;
    expect(health.healthy).toBe(false);
    expect(health.message).toBe(`Vault did not respond within 5s. Verify: curl -s ${TEST_ADDR}/v1/sys/health`);
  });
});
