import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as crypto from 'crypto';
import { GCPSecretManagerBackend, isGCPAvailable, encodeStoreKey, decodeStoreKey } from './gcp-sm';
import { McpVault } from '../mcp/vault';
import { fakeSecretManager, type FakeSecretManager } from './gcp-sm-fake.test-support';

const mockFetch = vi.fn();

beforeEach(() => {
  vi.stubGlobal('fetch', mockFetch);
  mockFetch.mockReset();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

const TEST_PROJECT = 'my-project-123';
const TEST_TOKEN = 'ya29.test-token';

/**
 * Create a GCPSecretManagerBackend with a pre-cached token to skip auth flow in tests.
 */
function createGCPBackend(overrides?: { projectId?: string }): GCPSecretManagerBackend {
  const backend = new GCPSecretManagerBackend({
    projectId: overrides?.projectId ?? TEST_PROJECT,
  });

  // Inject a cached token to bypass auth in unit tests
  (backend as any).accessToken = TEST_TOKEN;
  (backend as any).tokenExpiry = Date.now() + 3600_000;

  return backend;
}

describe('GCPSecretManagerBackend', () => {
  describe('resolve', () => {
    it('reads a secret and returns { path: value }', async () => {
      const secretValue = Buffer.from('my-secret-value').toString('base64');

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          payload: { data: secretValue },
        }),
      });

      const backend = createGCPBackend();
      const result = await backend.resolve('secret/MY_KEY');

      expect(result).toEqual({ 'secret/MY_KEY': 'my-secret-value' });
      expect(mockFetch).toHaveBeenCalledTimes(1);

      const [url, opts] = mockFetch.mock.calls[0];
      expect(url).toBe(
        `https://secretmanager.googleapis.com/v1/projects/${TEST_PROJECT}/secrets/MY_KEY/versions/latest:access`
      );
      expect(opts.method).toBe('GET');
      expect(opts.headers['Authorization']).toBe(`Bearer ${TEST_TOKEN}`);
    });

    it('lists the project for a prefix, with no read of a secret named after the prefix first', async () => {
      // List secrets
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          secrets: [
            { name: `projects/${TEST_PROJECT}/secrets/KEY_A` },
            { name: `projects/${TEST_PROJECT}/secrets/KEY_B` },
          ],
        }),
      });

      // Read KEY_A
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          payload: { data: Buffer.from('val-a').toString('base64') },
        }),
      });

      // Read KEY_B
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          payload: { data: Buffer.from('val-b').toString('base64') },
        }),
      });

      const backend = createGCPBackend();
      const result = await backend.resolve('secret');

      expect(result).toEqual({
        'secret/KEY_A': 'val-a',
        'secret/KEY_B': 'val-b',
      });
      expect(mockFetch.mock.calls.map(([url]) => url)).toEqual([
        `https://secretmanager.googleapis.com/v1/projects/${TEST_PROJECT}/secrets?pageSize=100`,
        `https://secretmanager.googleapis.com/v1/projects/${TEST_PROJECT}/secrets/KEY_A/versions/latest:access`,
        `https://secretmanager.googleapis.com/v1/projects/${TEST_PROJECT}/secrets/KEY_B/versions/latest:access`,
      ]);
    });

    it('returns empty for a prefix the project holds nothing under, after one list and no read', async () => {
      // List secrets -> empty
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ secrets: [] }),
      });

      const backend = createGCPBackend();
      const result = await backend.resolve('nonexistent');
      expect(result).toEqual({});
      expect(mockFetch).toHaveBeenCalledTimes(1);
      expect(mockFetch.mock.calls[0][0]).toBe(
        `https://secretmanager.googleapis.com/v1/projects/${TEST_PROJECT}/secrets?pageSize=100`,
      );
    });

    it('throws on 403', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 403,
        json: async () => ({}),
        text: async () => 'forbidden',
      });

      const backend = createGCPBackend();
      await expect(backend.resolve('secret/forbidden')).rejects.toThrow('IAM permissions');
    });
  });

  describe('store', () => {
    it('creates a secret and adds a version', async () => {
      // Create secret -> 200
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({}),
      });

      // Add version -> 200
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({}),
      });

      const backend = createGCPBackend();
      await backend.store('secret/my-key', 'my-value');

      expect(mockFetch).toHaveBeenCalledTimes(2);

      // Verify create call
      const [createUrl, createOpts] = mockFetch.mock.calls[0];
      expect(createUrl).toContain(`/secrets?secretId=my-key`);
      expect(createOpts.method).toBe('POST');

      // Verify add version call
      const [versionUrl, versionOpts] = mockFetch.mock.calls[1];
      expect(versionUrl).toContain('/secrets/my-key:addVersion');
      expect(versionOpts.method).toBe('POST');
      const body = JSON.parse(versionOpts.body);
      expect(Buffer.from(body.payload.data, 'base64').toString()).toBe('my-value');
    });

    it('adds a version to existing secret (409 on create)', async () => {
      // Create secret -> 409 (already exists)
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 409,
        json: async () => ({}),
      });

      // Add version -> 200
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({}),
      });

      const backend = createGCPBackend();
      await backend.store('secret/existing-key', 'updated-value');

      expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it('rejects invalid secret names with dots', async () => {
      const backend = createGCPBackend();
      await expect(backend.store('my.key', 'value')).rejects.toThrow(
        "Invalid secret name 'my.key'"
      );
    });

    it('rejects secret names with spaces', async () => {
      const backend = createGCPBackend();
      await expect(backend.store('my key', 'value')).rejects.toThrow(
        "Invalid secret name 'my key'"
      );
    });

    it('throws on 403', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 403,
        json: async () => ({}),
      });

      const backend = createGCPBackend();
      await expect(backend.store('secret/forbidden', 'value')).rejects.toThrow('IAM permissions');
    });
  });

  describe('delete', () => {
    it('deletes a secret', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({}),
      });

      const backend = createGCPBackend();
      const result = await backend.delete('secret/old-key');
      expect(result).toBe(true);

      const [url] = mockFetch.mock.calls[0];
      expect(url).toContain('/secrets/old-key');
    });

    it('returns false for 404', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
      });

      const backend = createGCPBackend();
      const result = await backend.delete('secret/nonexistent');
      expect(result).toBe(false);
    });

    it('throws on 403', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 403,
      });

      const backend = createGCPBackend();
      await expect(backend.delete('secret/forbidden')).rejects.toThrow('IAM permissions');
    });
  });

  describe('healthCheck', () => {
    it('returns healthy when list succeeds', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ secrets: [] }),
      });

      const backend = createGCPBackend();
      const health = await backend.healthCheck();

      expect(health.healthy).toBe(true);
      expect(health.message).toContain(TEST_PROJECT);
      expect(health.latencyMs).toBeGreaterThanOrEqual(0);
    });

    it('returns unhealthy on 403', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 403,
      });

      const backend = createGCPBackend();
      const health = await backend.healthCheck();

      expect(health.healthy).toBe(false);
      expect(health.message).toContain('IAM permissions');
    });

    it('returns unhealthy when connection fails', async () => {
      mockFetch.mockRejectedValueOnce(new Error('ECONNREFUSED'));

      const backend = createGCPBackend();
      const health = await backend.healthCheck();

      expect(health.healthy).toBe(false);
      expect(health.message).toBe('ECONNREFUSED');
    });

    it('returns unhealthy when project ID not configured', async () => {
      const backend = new GCPSecretManagerBackend({});
      // Mock the internal projectId resolution to return nothing
      (backend as any).resolveProjectId = () => undefined;

      const health = await backend.healthCheck();

      expect(health.healthy).toBe(false);
      expect(health.message).toContain('project ID');
    });
  });

  describe('secret name validation', () => {
    it('accepts valid names', async () => {
      // Create -> 200, Add version -> 200
      mockFetch.mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({}) });
      mockFetch.mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({}) });

      const backend = createGCPBackend();
      await expect(backend.store('secret/valid-name_123', 'value')).resolves.not.toThrow();
    });

    it('rejects names with special characters', async () => {
      const backend = createGCPBackend();
      await expect(backend.store('a@b', 'value')).rejects.toThrow('Invalid secret name');
    });

    it('rejects empty names', async () => {
      const backend = createGCPBackend();
      // store('secret/') -> secretName becomes ''
      await expect(backend.store('secret/', 'value')).rejects.toThrow('Invalid secret name');
    });
  });
});

describe('isGCPAvailable', () => {
  it('returns a result object with available and message', () => {
    const result = isGCPAvailable();
    expect(result).toHaveProperty('available');
    expect(result).toHaveProperty('message');
    expect(typeof result.available).toBe('boolean');
    expect(typeof result.message).toBe('string');
  });
});

describe('GCPSecretManagerBackend: every request is bounded end to end', () => {
  const VALUE = 'planted-gcp-value-4b9d';

  /** A fetch that honours its abort signal and otherwise never settles. */
  const silentFetch = (_url: string, init: { signal: AbortSignal }) =>
    new Promise((_, reject) => {
      init.signal.addEventListener('abort', () => reject(new DOMException('This operation was aborted', 'AbortError')));
    });

  beforeEach(() => { vi.useFakeTimers(); });
  afterEach(() => { vi.useRealTimers(); });

  it('a read the API never answers: throws within 10s, names the host and request, and says what to do', async () => {
    mockFetch.mockImplementationOnce(silentFetch);
    const outcome = createGCPBackend().resolve('secret/MY_KEY').then(() => null, (e: Error) => e);
    await vi.advanceTimersByTimeAsync(10_000);
    const err = await outcome;
    expect(err).toBeInstanceOf(Error);
    expect(err!.message).toContain(
      `GCP Secret Manager: secretmanager.googleapis.com did not respond within 10s (GET /v1/projects/${TEST_PROJECT}/secrets/MY_KEY/versions/latest:access)`,
    );
    expect(err!.message).toContain('Verify:  curl -sI https://secretmanager.googleapis.com/');
    expect(err!.message).toContain('Fix:');
    expect(err!.message).not.toContain('aborted');
  });

  it('a read whose body never arrives: the body read is under the same 10s bound', async () => {
    mockFetch.mockResolvedValueOnce({ ok: true, status: 200, json: () => new Promise(() => {}) });
    const outcome = createGCPBackend().resolve('secret/MY_KEY').then(() => null, (e: Error) => e);
    await vi.advanceTimersByTimeAsync(10_000);
    const err = await outcome;
    expect(err).toBeInstanceOf(Error);
    expect(err!.message).toContain('secretmanager.googleapis.com did not respond within 10s');
  });

  it('a write the API never answers: the error holds neither the token nor the value', async () => {
    mockFetch.mockImplementationOnce(silentFetch);
    const outcome = createGCPBackend().store('secret/MY_KEY', VALUE).then(() => null, (e: Error) => e);
    await vi.advanceTimersByTimeAsync(10_000);
    const err = await outcome;
    expect(err!.message).toContain('did not respond within 10s (POST ');
    expect(err!.message).not.toContain(VALUE);
    expect(err!.message).not.toContain(TEST_TOKEN);
  });

  it('a health check the API never answers: unhealthy within 5s, on one line, with a Verify command', async () => {
    mockFetch.mockImplementationOnce(silentFetch);
    const outcome = createGCPBackend().healthCheck();
    await vi.advanceTimersByTimeAsync(5_000);
    const health = await outcome;
    expect(health.healthy).toBe(false);
    expect(health.message).toBe('GCP Secret Manager did not respond within 5s. Verify: curl -sI https://secretmanager.googleapis.com/');
  });
});

/** The label a secret named after a whole store key carries. */
const STORE_KEY_LABELS = { 'secretless-ai': 'store-key' };

/** A value built at run time, shaped like no provider's token. */
function placeholder(label: string): string {
  return [label, 'placeholder', crypto.randomBytes(6).toString('hex')].join('-');
}

describe('GCPSecretManagerBackend: an MCP server reads and writes only its own secrets', () => {
  let project: FakeSecretManager;
  let vault: McpVault;

  beforeEach(() => {
    project = fakeSecretManager(TEST_PROJECT);
    mockFetch.mockImplementation(project.fetch);
    vault = new McpVault({ backend: createGCPBackend() });
  });

  it('(a) a server with nothing stored gets nothing, and no value in the project is read', async () => {
    project.put('DB_PASSWORD', placeholder('db'));
    project.put('STRIPE_KEY', placeholder('stripe'));

    expect(await vault.getServerSecrets('cursor', 'github')).toEqual({});
    expect(project.valueReads).toEqual([]);
  });

  it('(a) an exact read that finds nothing returns {} and sends no list', async () => {
    project.put('DB_PASSWORD', placeholder('db'));

    expect(await createGCPBackend().resolve('mcp/cursor/github/GITHUB_TOKEN', { exact: true })).toEqual({});
    expect(project.requests.filter((r) => r.startsWith(`GET /v1/projects/${TEST_PROJECT}/secrets?`))).toEqual([]);
    expect(project.valueReads).toEqual([]);
  });

  it('(a) an exact read of a server key is not answered by a project secret named like its env name', async () => {
    project.put('GITHUB_TOKEN', placeholder('user'));

    expect(await createGCPBackend().resolve('mcp/cursor/github/GITHUB_TOKEN', { exact: true })).toEqual({});
    expect(project.valueReads).toEqual([]);
  });

  it('(b) storing GITHUB_TOKEN for a server creates a secret of its own and leaves the project secret GITHUB_TOKEN as it was', async () => {
    const existing = placeholder('user');
    const stored = placeholder('github');
    project.put('GITHUB_TOKEN', existing);

    await vault.storeServerSecrets('cursor', 'github', { GITHUB_TOKEN: stored });

    expect(project.secrets.get('GITHUB_TOKEN')).toEqual({ labels: {}, versions: [existing] });
    const created = [...project.secrets.keys()].filter((name) => name !== 'GITHUB_TOKEN');
    expect(created).toHaveLength(1);
    expect(created[0]).not.toBe('GITHUB_TOKEN');
    expect(project.secrets.get(created[0])).toEqual({ labels: STORE_KEY_LABELS, versions: [stored] });
    expect(await vault.getServerSecrets('cursor', 'github')).toEqual({ GITHUB_TOKEN: stored });
  });

  it('(c) servers storing the same env name get one secret each, and each reads only its own', async () => {
    const pairs: Array<[string, string]> = [['cursor', 'github'], ['windsurf', 'github'], ['cursor', 'gitlab']];
    const values = new Map(pairs.map(([client, server]) => [`${client}/${server}`, placeholder(`${client}-${server}`)]));
    for (const [client, server] of pairs) {
      await vault.storeServerSecrets(client, server, { API_TOKEN: values.get(`${client}/${server}`)! });
    }

    expect(project.secrets.size).toBe(3);
    for (const [client, server] of pairs) {
      expect(await vault.getServerSecrets(client, server)).toEqual({ API_TOKEN: values.get(`${client}/${server}`) });
    }
  });

  it('(d) listEntries names only the stored pairs and reads no plain secret', async () => {
    project.put('DB_PASSWORD', placeholder('db'));
    project.put('STRIPE_KEY', placeholder('stripe'));
    project.put('ConnectionStrings--Default', placeholder('dotnet'));
    await vault.storeServerSecrets('cursor', 'github', { GITHUB_TOKEN: placeholder('github') });
    await vault.storeServerSecrets('windsurf', 'linear', { LINEAR_API_KEY: placeholder('linear'), LINEAR_TEAM_TOKEN: placeholder('team') });
    project.valueReads.length = 0;

    const entries = await vault.listEntries();

    expect(entries.sort((x, y) => `${x.client}/${x.server}`.localeCompare(`${y.client}/${y.server}`))).toEqual([
      { client: 'cursor', server: 'github', keyCount: 1 },
      { client: 'windsurf', server: 'linear', keyCount: 2 },
    ]);
    expect(project.valueReads.sort()).toEqual([
      'mcp--cursor--github--GITHUB__TOKEN',
      'mcp--windsurf--linear--LINEAR__API__KEY',
      'mcp--windsurf--linear--LINEAR__TEAM__TOKEN',
    ]);
  });

  it("removing a server's secrets deletes that server's and no other secret in the project", async () => {
    project.put('DB_PASSWORD', placeholder('db'));
    project.put('GITHUB_TOKEN', placeholder('user'));
    await vault.storeServerSecrets('cursor', 'github', { GITHUB_TOKEN: placeholder('github') });
    await vault.storeServerSecrets('cursor', 'gitlab', { GITLAB_TOKEN: placeholder('gitlab') });

    await vault.removeServerSecrets('cursor', 'github');

    expect([...project.secrets.keys()].sort()).toEqual(['DB_PASSWORD', 'GITHUB_TOKEN', 'mcp--cursor--gitlab--GITLAB__TOKEN']);
  });

  it('a secret under a derived name that this tool did not create is neither handed to the server nor written to', async () => {
    const other = placeholder('other');
    project.put('mcp--cursor--github--GITHUB__TOKEN', other);

    expect(await vault.getServerSecrets('cursor', 'github')).toEqual({});
    expect(project.valueReads).toEqual([]);
    await expect(vault.storeServerSecrets('cursor', 'github', { GITHUB_TOKEN: placeholder('github') })).rejects.toThrow(
      `holds a secret named mcp--cursor--github--GITHUB__TOKEN that secretless-ai did not create for the key 'mcp/cursor/github/GITHUB_TOKEN'`,
    );
    expect(await createGCPBackend().delete('mcp/cursor/github/GITHUB_TOKEN')).toBe(false);
    expect(project.secrets.get('mcp--cursor--github--GITHUB__TOKEN')).toEqual({ labels: {}, versions: [other] });
  });

  it('storing again for the same server adds a version to its own secret', async () => {
    const first = placeholder('first');
    const second = placeholder('second');
    await vault.storeServerSecrets('cursor', 'github', { GITHUB_TOKEN: first });
    await vault.storeServerSecrets('cursor', 'github', { GITHUB_TOKEN: second });

    expect(project.secrets.get('mcp--cursor--github--GITHUB__TOKEN')).toEqual({ labels: STORE_KEY_LABELS, versions: [first, second] });
    expect(await vault.getServerSecrets('cursor', 'github')).toEqual({ GITHUB_TOKEN: second });
  });

  it("a server's secret on a later page of the list is found, and no other value is read", async () => {
    for (let i = 0; i < 150; i++) project.put(`P${String(i).padStart(3, '0')}`, placeholder('plain'));
    const stored = placeholder('github');
    await vault.storeServerSecrets('cursor', 'github', { GITHUB_TOKEN: stored });
    project.valueReads.length = 0;

    expect(await vault.getServerSecrets('cursor', 'github')).toEqual({ GITHUB_TOKEN: stored });
    expect(project.requests.filter((r) => r.startsWith(`GET /v1/projects/${TEST_PROJECT}/secrets?`))).toEqual([
      `GET /v1/projects/${TEST_PROJECT}/secrets?pageSize=100`,
      `GET /v1/projects/${TEST_PROJECT}/secrets?pageSize=100&pageToken=100`,
    ]);
    expect(project.valueReads).toEqual(['mcp--cursor--github--GITHUB__TOKEN']);
  });

  it('a plain secret keeps its bare name: secret/NAME is stored, read and deleted as NAME', async () => {
    const value = placeholder('db');
    const backend = createGCPBackend();

    await backend.store('secret/DB_PASSWORD', value);
    expect(project.secrets.get('DB_PASSWORD')).toEqual({ labels: {}, versions: [value] });
    expect(await backend.resolve('secret/DB_PASSWORD', { exact: true })).toEqual({ 'secret/DB_PASSWORD': value });
    expect(await backend.delete('secret/DB_PASSWORD')).toBe(true);
    expect(project.secrets.has('DB_PASSWORD')).toBe(false);
  });

  it("resolve('secret') returns the project's plain secrets, a name holding '--' among them, and no MCP server's", async () => {
    const db = placeholder('db');
    const dotnet = placeholder('dotnet');
    project.put('DB_PASSWORD', db);
    project.put('ConnectionStrings--Default', dotnet);
    await vault.storeServerSecrets('cursor', 'github', { GITHUB_TOKEN: placeholder('github') });
    project.valueReads.length = 0;

    expect(await createGCPBackend().resolve('secret')).toEqual({
      'secret/DB_PASSWORD': db,
      'secret/ConnectionStrings--Default': dotnet,
    });
    expect(project.valueReads.sort()).toEqual(['ConnectionStrings--Default', 'DB_PASSWORD']);
  });
});

describe('encodeStoreKey and decodeStoreKey: one name per key, and back', () => {
  const SECRET_ID = /^[A-Za-z0-9_-]{1,255}$/;
  // Client and server names are what vault.ts takes ([A-Za-z0-9_-]+); an env
  // name is any key of a server's env.
  const clients = ['cursor', 'claude-desktop', 'windsurf', 'my_client', 'A-b_C', '-', '_', 'a--b', 'x-', '-x'];
  const servers = ['github', 'my-server', 'server_1', 'Z9', '_', '-', '__', 'a_2Db', 'mcp'];
  const envs = [
    'GITHUB_TOKEN', 'API_KEY', 'api-key', 'a.b', 'with space', 'x/y', '/', 'ü', '🙂', '_', '-', '--', '__',
    '_2D', 'a--b', '', 'K=V', '\u0000', '\u007f', 'Ω_ω',
  ];
  const keys = clients.flatMap((c) => servers.flatMap((s) => envs.map((e) => `mcp/${c}/${s}/${e}`)));

  it('(f) round trip: every key vault.ts can produce is named by a valid secret id that decodes back to it', () => {
    for (const key of keys) {
      const name = encodeStoreKey(key);
      expect(name, key).toMatch(SECRET_ID);
      expect(decodeStoreKey(name), key).toBe(key);
    }
  });

  it('(f) distinctness: no two of those keys share a name', () => {
    const names = new Map<string, string>();
    for (const key of keys) {
      const name = encodeStoreKey(key);
      expect(names.get(name) ?? key, name).toBe(key);
      names.set(name, key);
    }
    expect(names.size).toBe(new Set(keys).size);
  });

  it('(f) random keys over an alphabet of separators, escapes and multi-byte characters: round trip and distinctness', () => {
    let seed = 0x5eed1e55;
    const random = (): number => {
      seed = (seed + 0x6d2b79f5) | 0;
      let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
    const pick = <T>(xs: readonly T[]): T => xs[Math.floor(random() * xs.length)];
    const nameChars = ['a', 'Z', '0', '9', '_', '-'];
    const envTokens = ['A', 'z', '5', '_', '-', '.', '/', ' ', 'ü', '🙂', '_2D', '__', '--', '%', '\\', ':'];
    const word = (chars: readonly string[], min: number, max: number): string =>
      Array.from({ length: min + Math.floor(random() * (max - min + 1)) }, () => pick(chars)).join('');

    const names = new Map<string, string>();
    for (let i = 0; i < 3000; i++) {
      const key = `mcp/${word(nameChars, 1, 8)}/${word(nameChars, 1, 8)}/${word(envTokens, 0, 10)}`;
      const name = encodeStoreKey(key);
      expect(name, key).toMatch(SECRET_ID);
      expect(decodeStoreKey(name), key).toBe(key);
      expect(names.get(name) ?? key, name).toBe(key);
      names.set(name, key);
    }
  });

  it('(f) the name of an MCP key: segments joined with --, _ written __, and - written _2D', () => {
    expect(encodeStoreKey('mcp/cursor/github/GITHUB_TOKEN')).toBe('mcp--cursor--github--GITHUB__TOKEN');
    expect(encodeStoreKey('mcp/claude-desktop/my-server/API_KEY')).toBe('mcp--claude_2Ddesktop--my_2Dserver--API__KEY');
    expect(encodeStoreKey('mcp/cursor/github/a.b')).toBe('mcp--cursor--github--a_2Eb');
  });

  it('(f) a plain key keeps its bare name, and a bare name is not a key', () => {
    expect(encodeStoreKey('secret/DB_PASSWORD')).toBe('DB_PASSWORD');
    expect(encodeStoreKey('DB_PASSWORD')).toBe('DB_PASSWORD');
    expect(decodeStoreKey('DB_PASSWORD')).toBeUndefined();
    expect(decodeStoreKey('my-db-password')).toBeUndefined();
  });

  it('(f) a name encodeStoreKey never writes decodes to nothing', () => {
    for (const name of [
      'mcp--_41', // 'A' escaped: the encoding writes it as itself
      'mcp--a_5Fb', // '_' escaped as hex: the encoding writes '__'
      'mcp--a_2fb', // lower-case hex
      'mcp---a', // a segment holding '-'
      'mcp--a_', // a lone escape character
      'mcp--_FF', // not UTF-8
      'mcp--a_2Fb', // '/' inside a segment
      'secret--DB_PASSWORD', // the plain key secret/DB_PASSWORD is stored as DB_PASSWORD
    ]) {
      expect(decodeStoreKey(name), name).toBeUndefined();
    }
  });

  it('(f) length bound: a key whose name is 255 characters is taken, and one over it is refused before any request', async () => {
    const at = `mcp/c/s/${'A'.repeat(255 - 'mcp--c--s--'.length)}`;
    expect(encodeStoreKey(at)).toHaveLength(255);
    expect(encodeStoreKey(`mcp/c/s/${'_'.repeat(122)}`)).toHaveLength(255);

    const over = `mcp/c/s/${'A'.repeat(256 - 'mcp--c--s--'.length)}`;
    expect(() => encodeStoreKey(over)).toThrow('would be stored under a name of 256 characters, over the 255 a secret name may have');
    await expect(createGCPBackend().store(over, 'value')).rejects.toThrow('256 characters');
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('(f) a key that is not well-formed Unicode is refused', () => {
    expect(() => encodeStoreKey('mcp/c/s/\uD800')).toThrow('is not well-formed Unicode');
  });
});
