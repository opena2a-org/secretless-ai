import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as child_process from 'child_process';
import { MacOSKeychainBackend } from './keychain-macos';

vi.mock('child_process', () => ({
  execFileSync: vi.fn(),
}));

const mockExecFileSync = vi.mocked(child_process.execFileSync);

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-keychain-macos-test-'));
}

function cleanup(dir: string): void {
  fs.rmSync(dir, { recursive: true, force: true });
}

describe('MacOSKeychainBackend', () => {
  let dir: string;

  beforeEach(() => {
    dir = tmpDir();
    mockExecFileSync.mockReset();
  });

  afterEach(() => {
    cleanup(dir);
  });

  describe('store()', () => {
    it('calls security delete then add with correct args', async () => {
      const backend = new MacOSKeychainBackend({ storeDir: dir });

      // delete may throw (not found) — that's ok
      mockExecFileSync.mockImplementation((cmd, args) => {
        if (typeof cmd === 'string' && cmd === 'security' && Array.isArray(args) && args[0] === 'delete-generic-password') {
          throw new Error('not found');
        }
        return Buffer.from('');
      });

      await backend.store('mcp/client/server/KEY', 'secret-value');

      // Verify delete was attempted
      expect(mockExecFileSync).toHaveBeenCalledWith(
        'security',
        ['delete-generic-password', '-s', 'secretless', '-a', 'mcp/client/server/KEY'],
        expect.any(Object),
      );

      // Verify add was called
      expect(mockExecFileSync).toHaveBeenCalledWith(
        'security',
        ['add-generic-password', '-s', 'secretless', '-a', 'mcp/client/server/KEY', '-w', 'secret-value', '-U'],
        expect.any(Object),
      );
    });

    it('updates the key index file', async () => {
      const backend = new MacOSKeychainBackend({ storeDir: dir });
      mockExecFileSync.mockReturnValue(Buffer.from(''));

      await backend.store('mcp/client/server/KEY', 'val');

      const indexPath = path.join(dir, 'keychain-index.json');
      const index = JSON.parse(fs.readFileSync(indexPath, 'utf-8'));
      expect(index).toContain('mcp/client/server/KEY');
    });

    it('does not duplicate keys in index', async () => {
      const backend = new MacOSKeychainBackend({ storeDir: dir });
      mockExecFileSync.mockReturnValue(Buffer.from(''));

      await backend.store('mcp/client/server/KEY', 'val1');
      await backend.store('mcp/client/server/KEY', 'val2');

      const indexPath = path.join(dir, 'keychain-index.json');
      const index = JSON.parse(fs.readFileSync(indexPath, 'utf-8'));
      const count = index.filter((k: string) => k === 'mcp/client/server/KEY').length;
      expect(count).toBe(1);
    });
  });

  describe('resolve()', () => {
    it('resolves matching keys from index', async () => {
      const backend = new MacOSKeychainBackend({ storeDir: dir });

      // Pre-populate index
      const indexPath = path.join(dir, 'keychain-index.json');
      fs.writeFileSync(indexPath, JSON.stringify([
        'mcp/client/server/KEY1',
        'mcp/client/server/KEY2',
        'mcp/other/server/KEY3',
      ]));

      mockExecFileSync.mockImplementation((cmd, args) => {
        if (typeof cmd === 'string' && cmd === 'security' && Array.isArray(args)) {
          const account = args[args.indexOf('-a') + 1];
          if (account === 'mcp/client/server/KEY1') return 'value1\n' as unknown as Buffer;
          if (account === 'mcp/client/server/KEY2') return 'value2\n' as unknown as Buffer;
        }
        return '' as unknown as Buffer;
      });

      const result = await backend.resolve('mcp/client/server');
      expect(result).toEqual({
        'mcp/client/server/KEY1': 'value1',
        'mcp/client/server/KEY2': 'value2',
      });
    });

    it('returns empty object when no matching keys', async () => {
      const backend = new MacOSKeychainBackend({ storeDir: dir });

      const indexPath = path.join(dir, 'keychain-index.json');
      fs.writeFileSync(indexPath, JSON.stringify(['mcp/other/server/KEY']));

      const result = await backend.resolve('mcp/client/server');
      expect(result).toEqual({});
    });

    it('skips keys that fail to retrieve', async () => {
      const backend = new MacOSKeychainBackend({ storeDir: dir });

      const indexPath = path.join(dir, 'keychain-index.json');
      fs.writeFileSync(indexPath, JSON.stringify(['mcp/client/server/KEY1']));

      mockExecFileSync.mockImplementation(() => {
        throw new Error('not found');
      });

      const result = await backend.resolve('mcp/client/server');
      expect(result).toEqual({});
    });
  });

  describe('delete()', () => {
    it('calls security delete and removes from index', async () => {
      const backend = new MacOSKeychainBackend({ storeDir: dir });

      // Pre-populate index
      const indexPath = path.join(dir, 'keychain-index.json');
      fs.writeFileSync(indexPath, JSON.stringify(['mcp/client/server/KEY1', 'mcp/client/server/KEY2']));

      mockExecFileSync.mockReturnValue(Buffer.from(''));

      const result = await backend.delete('mcp/client/server/KEY1');
      expect(result).toBe(true);

      expect(mockExecFileSync).toHaveBeenCalledWith(
        'security',
        ['delete-generic-password', '-s', 'secretless', '-a', 'mcp/client/server/KEY1'],
        expect.any(Object),
      );

      // Index should no longer contain KEY1
      const updatedIndex = JSON.parse(fs.readFileSync(indexPath, 'utf-8'));
      expect(updatedIndex).not.toContain('mcp/client/server/KEY1');
      expect(updatedIndex).toContain('mcp/client/server/KEY2');
    });

    it('returns false when delete fails', async () => {
      const backend = new MacOSKeychainBackend({ storeDir: dir });

      mockExecFileSync.mockImplementation(() => {
        throw new Error('not found');
      });

      const result = await backend.delete('nonexistent');
      expect(result).toBe(false);
    });
  });

  describe('healthCheck()', () => {
    it('returns healthy when security command works', async () => {
      const backend = new MacOSKeychainBackend({ storeDir: dir });
      mockExecFileSync.mockReturnValue(Buffer.from(''));

      const health = await backend.healthCheck();
      expect(health.healthy).toBe(true);
      expect(health.message).toContain('macOS Keychain available');
    });

    it('returns unhealthy when security command fails', async () => {
      const backend = new MacOSKeychainBackend({ storeDir: dir });
      mockExecFileSync.mockImplementation(() => {
        throw new Error('no keychain');
      });

      const health = await backend.healthCheck();
      expect(health.healthy).toBe(false);
    });
  });
});
