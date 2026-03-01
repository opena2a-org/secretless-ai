import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as http from 'http';
import { AimClient } from './aim-client';

describe('AimClient', () => {
  let server: http.Server;
  let baseUrl: string;
  let client: AimClient;

  // Test data
  const mockAgent = {
    agentId: 'scanner-01',
    trustScore: 0.92,
    capabilities: ['scan', 'read-secrets'],
    verified: true,
  };

  beforeEach(async () => {
    // Start a local HTTP server to mock AIM
    server = http.createServer((req, res) => {
      if (req.url === '/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'healthy' }));
        return;
      }

      if (req.url === '/api/v1/agents/scanner-01') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(mockAgent));
        return;
      }

      if (req.url === '/api/v1/agents/unknown-agent') {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Not found' }));
        return;
      }

      if (req.url === '/api/v1/agents/malformed-agent') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ noAgentId: true }));
        return;
      }

      res.writeHead(404);
      res.end();
    });

    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', () => resolve());
    });

    const addr = server.address() as { port: number };
    baseUrl = `http://127.0.0.1:${addr.port}`;
    client = new AimClient(baseUrl, { cacheTtlMs: 1000 });
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
    });
  });

  describe('getAgentIdentity', () => {
    it('fetches agent identity from AIM', async () => {
      const identity = await client.getAgentIdentity('scanner-01');
      expect(identity).toBeDefined();
      expect(identity!.agentId).toBe('scanner-01');
      expect(identity!.trustScore).toBe(0.92);
      expect(identity!.capabilities).toContain('scan');
      expect(identity!.capabilities).toContain('read-secrets');
      expect(identity!.verified).toBe(true);
    });

    it('returns undefined for unknown agent', async () => {
      const identity = await client.getAgentIdentity('unknown-agent');
      expect(identity).toBeUndefined();
    });

    it('returns undefined for malformed response', async () => {
      const identity = await client.getAgentIdentity('malformed-agent');
      expect(identity).toBeUndefined();
    });

    it('returns undefined when server is unreachable', async () => {
      const offlineClient = new AimClient('http://127.0.0.1:1');
      const identity = await offlineClient.getAgentIdentity('any-agent');
      expect(identity).toBeUndefined();
    });
  });

  describe('caching', () => {
    it('caches agent identity', async () => {
      await client.getAgentIdentity('scanner-01');
      expect(client.cacheSize).toBe(1);

      // Second call should use cache (no network request)
      const identity = await client.getAgentIdentity('scanner-01');
      expect(identity).toBeDefined();
      expect(identity!.agentId).toBe('scanner-01');
    });

    it('evicts expired cache entries', async () => {
      const now = Date.now();
      vi.spyOn(Date, 'now').mockReturnValue(now);

      await client.getAgentIdentity('scanner-01');
      expect(client.cacheSize).toBe(1);

      // Advance time past TTL
      vi.spyOn(Date, 'now').mockReturnValue(now + 2000);

      // Should fetch again (cache expired)
      const identity = await client.getAgentIdentity('scanner-01');
      expect(identity).toBeDefined();
    });

    it('clears cache', async () => {
      await client.getAgentIdentity('scanner-01');
      expect(client.cacheSize).toBe(1);

      client.clearCache();
      expect(client.cacheSize).toBe(0);
    });

    it('evicts specific agent', async () => {
      await client.getAgentIdentity('scanner-01');
      expect(client.cacheSize).toBe(1);

      client.evict('scanner-01');
      expect(client.cacheSize).toBe(0);
    });

    it('does not cache failed lookups', async () => {
      await client.getAgentIdentity('unknown-agent');
      expect(client.cacheSize).toBe(0);
    });
  });

  describe('isAvailable', () => {
    it('returns true when server is reachable', async () => {
      const available = await client.isAvailable();
      expect(available).toBe(true);
    });

    it('returns false when server is unreachable', async () => {
      const offlineClient = new AimClient('http://127.0.0.1:1');
      const available = await offlineClient.isAvailable();
      expect(available).toBe(false);
    });
  });

  describe('trust score and capabilities', () => {
    it('returns numeric trust score', async () => {
      const identity = await client.getAgentIdentity('scanner-01');
      expect(typeof identity!.trustScore).toBe('number');
      expect(identity!.trustScore).toBeGreaterThanOrEqual(0);
      expect(identity!.trustScore).toBeLessThanOrEqual(1);
    });

    it('returns capabilities array', async () => {
      const identity = await client.getAgentIdentity('scanner-01');
      expect(Array.isArray(identity!.capabilities)).toBe(true);
      expect(identity!.capabilities.length).toBeGreaterThan(0);
    });
  });

  describe('URL handling', () => {
    it('strips trailing slashes from base URL', () => {
      const c = new AimClient('http://localhost:8080///');
      // Just verify construction does not throw
      expect(c).toBeDefined();
    });
  });
});
