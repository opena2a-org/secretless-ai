/**
 * The MCP vault reads one server's secrets as `resolve('mcp/<client>/<server>')`
 * and hands every entry it returns to that server. On the Vault and 1Password
 * backends the read is answered from the store's own key layout: these cells
 * check that it returns the entries under that pair and none of a pair that
 * shares the client.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as child_process from 'child_process';
import { VaultBackend } from './vault';
import { OnePasswordBackend } from './onepassword';

vi.mock('child_process', () => ({
  execFileSync: vi.fn(),
}));

const STORED: Record<string, string> = {
  'mcp/a/b/X': 'value-of-x',
  'mcp/a/c/Y': 'value-of-y',
};

describe('a read of one MCP pair returns only that pair', () => {
  describe('vault', () => {
    const ADDR = 'http://127.0.0.1:8200';
    const reads: string[] = [];

    /** A KV v2 mount at `secret/` holding STORED, answering GET and LIST. */
    const kv = async (input: string, init?: { method?: string }) => {
      const url = new URL(input);
      if (url.origin !== ADDR) throw new Error(`census stub: refused a request to ${url.origin}`);
      const method = init?.method ?? 'GET';
      const data = /^\/v1\/secret\/data\/(.+)$/.exec(url.pathname);
      if (data && method === 'GET') {
        const key = data[1].split('/').map(decodeURIComponent).join('/');
        if (!(key in STORED)) return { ok: false, status: 404, json: async () => ({}), text: async () => '' };
        reads.push(key);
        return { ok: true, status: 200, json: async () => ({ data: { data: { value: STORED[key] } } }), text: async () => '' };
      }
      const meta = /^\/v1\/secret\/metadata\/(.+)$/.exec(url.pathname);
      if (meta && method === 'LIST') {
        const prefix = `${meta[1].split('/').map(decodeURIComponent).join('/')}/`;
        const children = new Set<string>();
        for (const key of Object.keys(STORED)) {
          if (!key.startsWith(prefix)) continue;
          const rest = key.slice(prefix.length);
          children.add(rest.includes('/') ? `${rest.split('/')[0]}/` : rest);
        }
        if (children.size === 0) return { ok: false, status: 404, json: async () => ({}), text: async () => '' };
        return { ok: true, status: 200, json: async () => ({ data: { keys: [...children] } }), text: async () => '' };
      }
      throw new Error(`census stub: no route for ${method} ${url.pathname}`);
    };

    beforeEach(() => {
      reads.length = 0;
      vi.stubGlobal('fetch', vi.fn(kv));
    });
    afterEach(() => {
      vi.unstubAllGlobals();
    });

    it("resolve('mcp/a/b') over mcp/a/b/X and mcp/a/c/Y returns only X, and reads no value of mcp/a/c", async () => {
      const backend = new VaultBackend({ addr: ADDR, token: 'census-placeholder' });
      expect(await backend.resolve('mcp/a/b')).toEqual({ 'mcp/a/b/X': 'value-of-x' });
      expect(reads).toEqual(['mcp/a/b/X']);
    });
  });

  describe('1password', () => {
    const VAULT_ID = 'census-vault';
    const items = Object.entries(STORED).map(([title, password], i) => ({ id: `item-${i}`, title, password }));
    const reads: string[] = [];

    beforeEach(() => {
      reads.length = 0;
      vi.mocked(child_process.execFileSync).mockImplementation(((cmd: string, args: string[]) => {
        if (cmd !== 'op') throw new Error(`census stub: refused ${cmd}`);
        const sub = `${args[0]} ${args[1]}`;
        if (sub === 'vault get') return JSON.stringify({ id: VAULT_ID });
        if (sub === 'item list') return JSON.stringify(items.map(({ id, title }) => ({ id, title })));
        if (sub === 'item get') {
          const item = items.find((i) => i.id === args[2]);
          if (!item) throw new Error('item not found');
          reads.push(item.title);
          return JSON.stringify({ value: item.password });
        }
        throw new Error(`census stub: no answer for op ${sub}`);
      }) as unknown as typeof child_process.execFileSync);
    });
    afterEach(() => {
      vi.mocked(child_process.execFileSync).mockReset();
    });

    it("resolve('mcp/a/b') over mcp/a/b/X and mcp/a/c/Y returns only X, and reads no value of mcp/a/c", async () => {
      const backend = new OnePasswordBackend();
      expect(await backend.resolve('mcp/a/b')).toEqual({ 'mcp/a/b/X': 'value-of-x' });
      expect(reads).toEqual(['mcp/a/b/X']);
    });
  });
});
