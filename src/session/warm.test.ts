import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock all external dependencies to avoid filesystem side effects
vi.mock('./session-state', () => ({
  getSessionStatus: vi.fn().mockReturnValue({
    warm: false,
    remainingSeconds: 0,
    expiresAt: '',
    authenticatedAt: '',
    ttlSeconds: 300,
  }),
  writeSessionState: vi.fn(),
  clearSessionState: vi.fn(),
}));

vi.mock('../backends/factory', () => ({
  createBackend: vi.fn(),
}));

vi.mock('../backends/config', () => ({
  resolveBackendType: vi.fn().mockReturnValue('local'),
  readCacheTtl: vi.fn().mockReturnValue(300),
  writeCacheTtl: vi.fn(),
}));

vi.mock('./touchid', () => ({
  warmSession: vi.fn().mockResolvedValue({
    warm: true,
    remainingSeconds: 300,
    expiresAt: new Date(Date.now() + 300000).toISOString(),
    authenticatedAt: new Date().toISOString(),
    ttlSeconds: 300,
  }),
  isMacOS: vi.fn().mockReturnValue(false),
  isTouchIDAvailable: vi.fn().mockReturnValue(false),
}));

vi.mock('../broker/daemon', () => ({
  isDaemonRunning: vi.fn().mockReturnValue(false),
  startDaemon: vi.fn().mockResolvedValue(undefined),
  getDaemonStatus: vi.fn().mockReturnValue({}),
}));

import { warm, preloadCache } from './warm';
import { getSessionStatus } from './session-state';
import { createBackend } from '../backends/factory';
import { resolveBackendType, readCacheTtl, writeCacheTtl } from '../backends/config';

describe('warm', () => {
  beforeEach(() => {
    vi.clearAllMocks();

    // Default: session is not warm
    vi.mocked(getSessionStatus).mockReturnValue({
      warm: false,
      remainingSeconds: 0,
      expiresAt: '',
      authenticatedAt: '',
      ttlSeconds: 300,
    });
  });

  describe('warm()', () => {
    it('returns sessionWarm=true after successful warmup', async () => {
      const result = await warm(300);
      expect(result.sessionWarm).toBe(true);
    });

    it('skips preload for local backend', async () => {
      vi.mocked(resolveBackendType).mockReturnValue('local');
      const result = await warm(300);
      expect(result.cachePreloaded).toBe(0);
      expect(createBackend).not.toHaveBeenCalled();
    });

    it('preloads secrets for 1password backend', async () => {
      vi.mocked(resolveBackendType).mockReturnValue('1password');
      vi.mocked(readCacheTtl).mockReturnValue(300);

      const mockBackend = {
        name: 'cached(1password)',
        resolve: vi.fn()
          .mockResolvedValueOnce({
            'secret/API_KEY': 'key123',
            'secret/DB_PASS': 'pass456',
          })
          .mockResolvedValueOnce({
            'mcp/claude/server/TOKEN': 'tok789',
          }),
        store: vi.fn(),
        delete: vi.fn(),
        healthCheck: vi.fn(),
      };
      vi.mocked(createBackend).mockReturnValue(mockBackend as any);

      const result = await warm(600);

      expect(result.cachePreloaded).toBe(3);
      expect(createBackend).toHaveBeenCalledWith('1password');
      expect(mockBackend.resolve).toHaveBeenCalledWith('secret');
      expect(mockBackend.resolve).toHaveBeenCalledWith('mcp');
    });

    it('syncs cache TTL when session TTL is longer', async () => {
      vi.mocked(resolveBackendType).mockReturnValue('1password');
      vi.mocked(readCacheTtl).mockReturnValue(300);

      const mockBackend = {
        name: 'cached(1password)',
        resolve: vi.fn().mockResolvedValue({}),
        store: vi.fn(),
        delete: vi.fn(),
        healthCheck: vi.fn(),
      };
      vi.mocked(createBackend).mockReturnValue(mockBackend as any);

      await warm(600);

      expect(writeCacheTtl).toHaveBeenCalledWith(600);
    });

    it('does not lower cache TTL when already sufficient', async () => {
      vi.mocked(resolveBackendType).mockReturnValue('keychain');
      vi.mocked(readCacheTtl).mockReturnValue(600);

      const mockBackend = {
        name: 'cached(keychain)',
        resolve: vi.fn().mockResolvedValue({}),
        store: vi.fn(),
        delete: vi.fn(),
        healthCheck: vi.fn(),
      };
      vi.mocked(createBackend).mockReturnValue(mockBackend as any);

      await warm(300);

      expect(writeCacheTtl).not.toHaveBeenCalled();
    });

    it('handles preload failure gracefully', async () => {
      vi.mocked(resolveBackendType).mockReturnValue('1password');
      vi.mocked(readCacheTtl).mockReturnValue(300);

      const mockBackend = {
        name: 'cached(1password)',
        resolve: vi.fn().mockRejectedValue(new Error('op not signed in')),
        store: vi.fn(),
        delete: vi.fn(),
        healthCheck: vi.fn(),
      };
      vi.mocked(createBackend).mockReturnValue(mockBackend as any);

      const result = await warm(300);

      // Session is still warm even if preload fails
      expect(result.sessionWarm).toBe(true);
      expect(result.cachePreloaded).toBe(0);
    });

    it('returns early if session is already warm', async () => {
      vi.mocked(getSessionStatus).mockReturnValue({
        warm: true,
        remainingSeconds: 250,
        expiresAt: new Date(Date.now() + 250000).toISOString(),
        authenticatedAt: new Date().toISOString(),
        ttlSeconds: 300,
      });

      const result = await warm(300);

      expect(result.sessionWarm).toBe(true);
      expect(result.cachePreloaded).toBe(0);
      expect(createBackend).not.toHaveBeenCalled();
    });
  });

  describe('preloadCache()', () => {
    it('returns 0 for local backend without calling createBackend', async () => {
      vi.mocked(resolveBackendType).mockReturnValue('local');

      const count = await preloadCache(300);

      expect(count).toBe(0);
      expect(createBackend).not.toHaveBeenCalled();
    });

    it('resolves both secret and mcp prefixes', async () => {
      vi.mocked(resolveBackendType).mockReturnValue('1password');
      vi.mocked(readCacheTtl).mockReturnValue(300);

      const mockBackend = {
        name: 'cached(1password)',
        resolve: vi.fn()
          .mockResolvedValueOnce({ 'secret/KEY1': 'v1' })
          .mockResolvedValueOnce({ 'mcp/c/s/KEY2': 'v2' }),
        store: vi.fn(),
        delete: vi.fn(),
        healthCheck: vi.fn(),
      };
      vi.mocked(createBackend).mockReturnValue(mockBackend as any);

      const count = await preloadCache(300);

      expect(count).toBe(2);
      expect(mockBackend.resolve).toHaveBeenCalledTimes(2);
    });

    it('handles empty vaults', async () => {
      vi.mocked(resolveBackendType).mockReturnValue('keychain');
      vi.mocked(readCacheTtl).mockReturnValue(300);

      const mockBackend = {
        name: 'cached(keychain)',
        resolve: vi.fn().mockResolvedValue({}),
        store: vi.fn(),
        delete: vi.fn(),
        healthCheck: vi.fn(),
      };
      vi.mocked(createBackend).mockReturnValue(mockBackend as any);

      const count = await preloadCache(300);

      expect(count).toBe(0);
    });

    it('counts secrets correctly when one prefix fails', async () => {
      vi.mocked(resolveBackendType).mockReturnValue('vault');
      vi.mocked(readCacheTtl).mockReturnValue(300);

      const mockBackend = {
        name: 'cached(vault)',
        resolve: vi.fn()
          .mockResolvedValueOnce({ 'secret/A': '1', 'secret/B': '2' })
          .mockRejectedValueOnce(new Error('MCP vault not configured')),
        store: vi.fn(),
        delete: vi.fn(),
        healthCheck: vi.fn(),
      };
      vi.mocked(createBackend).mockReturnValue(mockBackend as any);

      const count = await preloadCache(300);

      expect(count).toBe(2);
    });

    it('preloads for vault backend', async () => {
      vi.mocked(resolveBackendType).mockReturnValue('vault');
      vi.mocked(readCacheTtl).mockReturnValue(300);

      const mockBackend = {
        name: 'cached(vault)',
        resolve: vi.fn().mockResolvedValue({ 'secret/TOKEN': 'abc' }),
        store: vi.fn(),
        delete: vi.fn(),
        healthCheck: vi.fn(),
      };
      vi.mocked(createBackend).mockReturnValue(mockBackend as any);

      const count = await preloadCache(300);

      expect(count).toBeGreaterThanOrEqual(1);
      expect(createBackend).toHaveBeenCalledWith('vault');
    });
  });
});
