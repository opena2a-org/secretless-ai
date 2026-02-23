import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as child_process from 'child_process';
import { OnePasswordBackend } from './onepassword';

vi.mock('child_process', () => ({
  execFileSync: vi.fn(),
}));

const mockExecFileSync = vi.mocked(child_process.execFileSync);

const VAULT_ID = 'vault-abc-123';

/** Simulate `op vault get` returning the Secretless vault. */
function mockVaultExists(): void {
  mockExecFileSync.mockImplementation((cmd, args) => {
    if (cmd === 'op' && Array.isArray(args) && args[0] === 'vault' && args[1] === 'get') {
      return JSON.stringify({ id: VAULT_ID }) as unknown as Buffer;
    }
    return '' as unknown as Buffer;
  });
}

/** Build a full mock that handles vault get, item list, item get, and CRUD. */
function mockOpCli(items: Array<{ id: string; title: string; password: string }>): void {
  mockExecFileSync.mockImplementation((cmd, args) => {
    if (cmd !== 'op' || !Array.isArray(args)) return '' as unknown as Buffer;

    const sub = `${args[0]} ${args[1]}`;

    if (sub === 'vault get') {
      return JSON.stringify({ id: VAULT_ID }) as unknown as Buffer;
    }

    if (sub === 'vault create') {
      return JSON.stringify({ id: VAULT_ID }) as unknown as Buffer;
    }

    if (sub === 'item list') {
      const listed = items.map(i => ({ id: i.id, title: i.title }));
      return JSON.stringify(listed) as unknown as Buffer;
    }

    if (sub === 'item get') {
      const itemId = args[2];
      const found = items.find(i => i.id === itemId);
      if (!found) throw new Error('item not found');
      return JSON.stringify({ value: found.password }) as unknown as Buffer;
    }

    if (sub === 'item create') {
      return '' as unknown as Buffer;
    }

    if (sub === 'item delete') {
      const title = args[2];
      const found = items.find(i => i.title === title);
      if (!found) throw new Error('item not found');
      return '' as unknown as Buffer;
    }

    if (sub === 'account get') {
      return JSON.stringify({ id: 'acct-1' }) as unknown as Buffer;
    }

    return '' as unknown as Buffer;
  });
}

describe('OnePasswordBackend', () => {
  beforeEach(() => {
    mockExecFileSync.mockReset();
  });

  describe('store()', () => {
    it('calls op item delete then create with correct args', async () => {
      mockOpCli([]);
      const backend = new OnePasswordBackend();

      await backend.store('secret/API_KEY', 'sk-12345');

      // Verify vault lookup
      expect(mockExecFileSync).toHaveBeenCalledWith(
        'op',
        ['vault', 'get', 'Secretless', '--format', 'json'],
        expect.any(Object),
      );

      // Verify item delete was attempted (may fail — that's fine)
      expect(mockExecFileSync).toHaveBeenCalledWith(
        'op',
        ['item', 'delete', 'secret/API_KEY', '--vault', VAULT_ID],
        expect.any(Object),
      );

      // Verify item create
      expect(mockExecFileSync).toHaveBeenCalledWith(
        'op',
        [
          'item', 'create',
          '--vault', VAULT_ID,
          '--category', 'Password',
          '--title', 'secret/API_KEY',
          '--tags', 'secretless',
          'password=sk-12345',
        ],
        expect.any(Object),
      );
    });

    it('creates vault when it does not exist', async () => {
      mockExecFileSync.mockImplementation((cmd, args) => {
        if (cmd !== 'op' || !Array.isArray(args)) return '' as unknown as Buffer;

        const sub = `${args[0]} ${args[1]}`;

        if (sub === 'vault get') {
          throw new Error('vault not found');
        }
        if (sub === 'vault create') {
          return JSON.stringify({ id: 'new-vault-id' }) as unknown as Buffer;
        }
        if (sub === 'item delete') {
          throw new Error('not found');
        }
        return '' as unknown as Buffer;
      });

      const backend = new OnePasswordBackend();
      await backend.store('secret/KEY', 'value');

      expect(mockExecFileSync).toHaveBeenCalledWith(
        'op',
        ['vault', 'create', 'Secretless', '--format', 'json'],
        expect.any(Object),
      );
    });

    it('uses custom vault name from config', async () => {
      mockExecFileSync.mockImplementation((cmd, args) => {
        if (cmd !== 'op' || !Array.isArray(args)) return '' as unknown as Buffer;

        if (args[0] === 'vault' && args[1] === 'get') {
          expect(args[2]).toBe('MyVault');
          return JSON.stringify({ id: 'custom-id' }) as unknown as Buffer;
        }
        if (args[0] === 'item' && args[1] === 'delete') {
          throw new Error('not found');
        }
        return '' as unknown as Buffer;
      });

      const backend = new OnePasswordBackend({ vault: 'MyVault' });
      await backend.store('secret/KEY', 'val');
    });
  });

  describe('resolve()', () => {
    it('resolves matching keys by prefix', async () => {
      mockOpCli([
        { id: 'item-1', title: 'mcp/client/server/KEY1', password: 'val1' },
        { id: 'item-2', title: 'mcp/client/server/KEY2', password: 'val2' },
        { id: 'item-3', title: 'mcp/other/KEY3', password: 'val3' },
        { id: 'item-4', title: 'secret/TOKEN', password: 'tok' },
      ]);

      const backend = new OnePasswordBackend();
      const result = await backend.resolve('mcp/client/server');

      expect(result).toEqual({
        'mcp/client/server/KEY1': 'val1',
        'mcp/client/server/KEY2': 'val2',
      });
    });

    it('resolves exact key match', async () => {
      mockOpCli([
        { id: 'item-1', title: 'secret/TOKEN', password: 'tok' },
      ]);

      const backend = new OnePasswordBackend();
      const result = await backend.resolve('secret/TOKEN');

      expect(result).toEqual({ 'secret/TOKEN': 'tok' });
    });

    it('returns empty when no matching keys', async () => {
      mockOpCli([
        { id: 'item-1', title: 'mcp/other/KEY', password: 'val' },
      ]);

      const backend = new OnePasswordBackend();
      const result = await backend.resolve('secret');

      expect(result).toEqual({});
    });

    it('returns empty when vault does not exist', async () => {
      mockExecFileSync.mockImplementation(() => {
        throw new Error('vault not found');
      });

      const backend = new OnePasswordBackend();
      const result = await backend.resolve('mcp');

      expect(result).toEqual({});
    });

    it('skips items whose password cannot be read', async () => {
      mockExecFileSync.mockImplementation((cmd, args) => {
        if (cmd !== 'op' || !Array.isArray(args)) return '' as unknown as Buffer;

        const sub = `${args[0]} ${args[1]}`;

        if (sub === 'vault get') {
          return JSON.stringify({ id: VAULT_ID }) as unknown as Buffer;
        }
        if (sub === 'item list') {
          return JSON.stringify([
            { id: 'item-1', title: 'mcp/KEY1' },
            { id: 'item-2', title: 'mcp/KEY2' },
          ]) as unknown as Buffer;
        }
        if (sub === 'item get') {
          const itemId = args[2];
          if (itemId === 'item-1') {
            return JSON.stringify({ value: 'val1' }) as unknown as Buffer;
          }
          throw new Error('access denied');
        }
        return '' as unknown as Buffer;
      });

      const backend = new OnePasswordBackend();
      const result = await backend.resolve('mcp');

      expect(result).toEqual({ 'mcp/KEY1': 'val1' });
    });

    it('does not match partial prefix without slash boundary', async () => {
      mockOpCli([
        { id: 'item-1', title: 'mcp-extra/KEY', password: 'val' },
        { id: 'item-2', title: 'mcp/KEY', password: 'val2' },
      ]);

      const backend = new OnePasswordBackend();
      const result = await backend.resolve('mcp');

      expect(result).toEqual({ 'mcp/KEY': 'val2' });
    });
  });

  describe('delete()', () => {
    it('deletes item by title and returns true', async () => {
      mockOpCli([
        { id: 'item-1', title: 'secret/TOKEN', password: 'tok' },
      ]);

      const backend = new OnePasswordBackend();
      const result = await backend.delete('secret/TOKEN');

      expect(result).toBe(true);
      expect(mockExecFileSync).toHaveBeenCalledWith(
        'op',
        ['item', 'delete', 'secret/TOKEN', '--vault', VAULT_ID],
        expect.any(Object),
      );
    });

    it('returns false when item does not exist', async () => {
      mockExecFileSync.mockImplementation((cmd, args) => {
        if (cmd !== 'op' || !Array.isArray(args)) return '' as unknown as Buffer;
        if (args[0] === 'vault' && args[1] === 'get') {
          return JSON.stringify({ id: VAULT_ID }) as unknown as Buffer;
        }
        throw new Error('item not found');
      });

      const backend = new OnePasswordBackend();
      const result = await backend.delete('nonexistent');

      expect(result).toBe(false);
    });

    it('returns false when vault does not exist', async () => {
      mockExecFileSync.mockImplementation(() => {
        throw new Error('vault not found');
      });

      const backend = new OnePasswordBackend();
      const result = await backend.delete('secret/KEY');

      expect(result).toBe(false);
    });
  });

  describe('healthCheck()', () => {
    it('returns healthy when op account get succeeds', async () => {
      mockExecFileSync.mockReturnValue(
        JSON.stringify({ id: 'account-1' }) as unknown as Buffer,
      );

      const backend = new OnePasswordBackend();
      const health = await backend.healthCheck();

      expect(health.healthy).toBe(true);
      expect(health.message).toBe('1Password CLI authenticated');
      expect(typeof health.latencyMs).toBe('number');
    });

    it('returns unhealthy when op is not authenticated', async () => {
      mockExecFileSync.mockImplementation(() => {
        throw new Error('not signed in');
      });

      const backend = new OnePasswordBackend();
      const health = await backend.healthCheck();

      expect(health.healthy).toBe(false);
      expect(health.message).toContain('not authenticated');
    });

    it('returns unhealthy when op CLI is not installed', async () => {
      mockExecFileSync.mockImplementation(() => {
        const err = new Error('ENOENT') as NodeJS.ErrnoException;
        err.code = 'ENOENT';
        throw err;
      });

      const backend = new OnePasswordBackend();
      const health = await backend.healthCheck();

      expect(health.healthy).toBe(false);
    });
  });

  describe('vault caching', () => {
    it('caches vault ID across multiple operations', async () => {
      mockOpCli([]);
      const backend = new OnePasswordBackend();

      await backend.resolve('mcp');
      await backend.resolve('secret');

      // vault get should only be called once (cached after first call)
      const vaultGetCalls = mockExecFileSync.mock.calls.filter(
        call => call[0] === 'op' && Array.isArray(call[1]) &&
          call[1][0] === 'vault' && call[1][1] === 'get',
      );
      expect(vaultGetCalls.length).toBe(1);
    });
  });
});
