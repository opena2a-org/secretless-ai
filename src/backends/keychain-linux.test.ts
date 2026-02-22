import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as child_process from 'child_process';
import { LinuxKeychainBackend } from './keychain-linux';

vi.mock('child_process', () => ({
  execFileSync: vi.fn(),
}));

const mockExecFileSync = vi.mocked(child_process.execFileSync);

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-keychain-linux-test-'));
}

function cleanup(dir: string): void {
  fs.rmSync(dir, { recursive: true, force: true });
}

describe('LinuxKeychainBackend', () => {
  let dir: string;

  beforeEach(() => {
    dir = tmpDir();
    mockExecFileSync.mockReset();
  });

  afterEach(() => {
    cleanup(dir);
  });

  describe('store()', () => {
    it('calls secret-tool store with value via stdin', async () => {
      const backend = new LinuxKeychainBackend({ storeDir: dir });
      mockExecFileSync.mockReturnValue(Buffer.from(''));

      await backend.store('mcp/client/server/KEY', 'secret-value');

      expect(mockExecFileSync).toHaveBeenCalledWith(
        'secret-tool',
        ['store', '--label=secretless', 'service', 'secretless', 'account', 'mcp/client/server/KEY'],
        expect.objectContaining({ input: 'secret-value' }),
      );
    });

    it('updates the key index file', async () => {
      const backend = new LinuxKeychainBackend({ storeDir: dir });
      mockExecFileSync.mockReturnValue(Buffer.from(''));

      await backend.store('mcp/client/server/KEY', 'val');

      const indexPath = path.join(dir, 'keychain-index.json');
      const index = JSON.parse(fs.readFileSync(indexPath, 'utf-8'));
      expect(index).toContain('mcp/client/server/KEY');
    });
  });

  describe('resolve()', () => {
    it('resolves matching keys from index', async () => {
      const backend = new LinuxKeychainBackend({ storeDir: dir });

      const indexPath = path.join(dir, 'keychain-index.json');
      fs.writeFileSync(indexPath, JSON.stringify([
        'mcp/client/server/KEY1',
        'mcp/client/server/KEY2',
      ]));

      mockExecFileSync.mockImplementation((_cmd, args) => {
        if (Array.isArray(args)) {
          const account = args[args.indexOf('account') + 1];
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
  });

  describe('delete()', () => {
    it('calls secret-tool clear and removes from index', async () => {
      const backend = new LinuxKeychainBackend({ storeDir: dir });

      const indexPath = path.join(dir, 'keychain-index.json');
      fs.writeFileSync(indexPath, JSON.stringify(['mcp/client/server/KEY1']));

      mockExecFileSync.mockReturnValue(Buffer.from(''));

      const result = await backend.delete('mcp/client/server/KEY1');
      expect(result).toBe(true);

      expect(mockExecFileSync).toHaveBeenCalledWith(
        'secret-tool',
        ['clear', 'service', 'secretless', 'account', 'mcp/client/server/KEY1'],
        expect.any(Object),
      );

      const updatedIndex = JSON.parse(fs.readFileSync(indexPath, 'utf-8'));
      expect(updatedIndex).not.toContain('mcp/client/server/KEY1');
    });

    it('returns false when delete fails', async () => {
      const backend = new LinuxKeychainBackend({ storeDir: dir });
      mockExecFileSync.mockImplementation(() => {
        throw new Error('not found');
      });

      const result = await backend.delete('nonexistent');
      expect(result).toBe(false);
    });
  });

  describe('healthCheck()', () => {
    it('returns healthy when secret-tool is found', async () => {
      const backend = new LinuxKeychainBackend({ storeDir: dir });
      mockExecFileSync.mockReturnValue(Buffer.from('/usr/bin/secret-tool'));

      const health = await backend.healthCheck();
      expect(health.healthy).toBe(true);
      expect(health.message).toContain('secret-tool available');
    });

    it('returns unhealthy when secret-tool is not found', async () => {
      const backend = new LinuxKeychainBackend({ storeDir: dir });
      mockExecFileSync.mockImplementation(() => {
        throw new Error('not found');
      });

      const health = await backend.healthCheck();
      expect(health.healthy).toBe(false);
      expect(health.message).toContain('secret-tool not found');
    });
  });
});
