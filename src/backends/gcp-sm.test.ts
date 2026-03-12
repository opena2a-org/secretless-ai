import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { GCPSecretManagerBackend, isGCPAvailable } from './gcp-sm';

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

    it('lists secrets when direct read returns 404 (prefix mode)', async () => {
      // Direct read of "secret" -> 404
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
        json: async () => ({}),
        text: async () => 'not found',
      });

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
    });

    it('returns empty when secret not found and list returns nothing', async () => {
      // Direct read -> 404
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
        json: async () => ({}),
        text: async () => 'not found',
      });

      // List secrets -> empty
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ secrets: [] }),
      });

      const backend = createGCPBackend();
      const result = await backend.resolve('nonexistent');
      expect(result).toEqual({});
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
