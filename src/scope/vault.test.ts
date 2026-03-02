import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { VaultScopeProvider } from './vault';

const mockFetch = vi.fn();

beforeEach(() => {
  vi.stubGlobal('fetch', mockFetch);
  mockFetch.mockReset();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

const TEST_ADDR = 'http://127.0.0.1:8200';
const TEST_TOKEN = 'hvs.test-scope-token';

describe('VaultScopeProvider', () => {
  describe('discover', () => {
    it('returns permissions from capabilities-self response', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          data: {
            'secret/data/*': ['create', 'read', 'update', 'delete', 'list'],
            'auth/token/lookup-self': ['read'],
            'sys/mounts': ['read'],
          },
        }),
      });

      const provider = new VaultScopeProvider(TEST_ADDR, TEST_TOKEN);
      const permissions = await provider.discover();

      expect(permissions).toContain('secret/data/*:read');
      expect(permissions).toContain('secret/data/*:create');
      expect(permissions).toContain('auth/token/lookup-self:read');
      expect(permissions).toContain('sys/mounts:read');

      // Verify correct request
      const [url, opts] = mockFetch.mock.calls[0];
      expect(url).toBe(`${TEST_ADDR}/v1/sys/capabilities-self`);
      expect(opts.method).toBe('POST');
      expect(opts.headers['X-Vault-Token']).toBe(TEST_TOKEN);
    });

    it('filters out deny capabilities', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          data: {
            'secret/data/*': ['read', 'deny'],
            'sys/seal': ['deny'],
          },
        }),
      });

      const provider = new VaultScopeProvider(TEST_ADDR, TEST_TOKEN);
      const permissions = await provider.discover();

      expect(permissions).toContain('secret/data/*:read');
      expect(permissions).not.toContain('secret/data/*:deny');
      expect(permissions).not.toContain('sys/seal:deny');
    });

    it('handles token with limited capabilities', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          data: {
            'secret/data/my-app/*': ['read'],
          },
        }),
      });

      const provider = new VaultScopeProvider(TEST_ADDR, TEST_TOKEN);
      const permissions = await provider.discover();

      expect(permissions).toEqual(['secret/data/my-app/*:read']);
    });

    it('handles root token with all capabilities', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          data: {
            'secret/data/*': ['create', 'read', 'update', 'delete', 'list', 'sudo', 'root'],
            'auth/token/lookup-self': ['read', 'sudo'],
            'sys/mounts': ['create', 'read', 'update', 'delete', 'list', 'sudo'],
            'sys/policies/acl': ['create', 'read', 'update', 'delete', 'list', 'sudo'],
          },
        }),
      });

      const provider = new VaultScopeProvider(TEST_ADDR, TEST_TOKEN);
      const permissions = await provider.discover();

      expect(permissions.length).toBeGreaterThan(10);
      expect(permissions).toContain('secret/data/*:root');
      expect(permissions).toContain('sys/mounts:sudo');
    });

    it('throws when VAULT_ADDR not set', async () => {
      const provider = new VaultScopeProvider('', TEST_TOKEN);
      await expect(provider.discover()).rejects.toThrow('VAULT_ADDR not set');
    });

    it('throws when VAULT_TOKEN not set', async () => {
      const provider = new VaultScopeProvider(TEST_ADDR, '');
      await expect(provider.discover()).rejects.toThrow('VAULT_TOKEN not set');
    });

    it('handles server unreachable', async () => {
      mockFetch.mockRejectedValueOnce(new Error('ECONNREFUSED'));

      const provider = new VaultScopeProvider(TEST_ADDR, TEST_TOKEN);
      await expect(provider.discover()).rejects.toThrow();
    });
  });

  describe('healthCheck', () => {
    it('returns true for healthy Vault', async () => {
      mockFetch.mockResolvedValueOnce({
        status: 200,
        ok: true,
      });

      const provider = new VaultScopeProvider(TEST_ADDR, TEST_TOKEN);
      expect(await provider.healthCheck()).toBe(true);
    });

    it('returns true for standby Vault (429)', async () => {
      mockFetch.mockResolvedValueOnce({
        status: 429,
        ok: false,
      });

      const provider = new VaultScopeProvider(TEST_ADDR, TEST_TOKEN);
      expect(await provider.healthCheck()).toBe(true);
    });

    it('returns false for sealed Vault (503)', async () => {
      mockFetch.mockResolvedValueOnce({
        status: 503,
        ok: false,
      });

      const provider = new VaultScopeProvider(TEST_ADDR, TEST_TOKEN);
      expect(await provider.healthCheck()).toBe(false);
    });

    it('returns false when not configured', async () => {
      const provider = new VaultScopeProvider('', '');
      expect(await provider.healthCheck()).toBe(false);
    });

    it('returns false on connection error', async () => {
      mockFetch.mockRejectedValueOnce(new Error('ECONNREFUSED'));

      const provider = new VaultScopeProvider(TEST_ADDR, TEST_TOKEN);
      expect(await provider.healthCheck()).toBe(false);
    });
  });
});
