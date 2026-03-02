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
