import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as child_process from 'child_process';
import {
  MacOSKeychainBackend,
  decodeKeychainValue,
  keychainOutputIsHexEncoded,
} from './keychain-macos';

vi.mock('child_process', () => ({
  execFileSync: vi.fn(),
  spawnSync: vi.fn(),
}));

const mockExecFileSync = vi.mocked(child_process.execFileSync);
const mockSpawnSync = vi.mocked(child_process.spawnSync);

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
    mockSpawnSync.mockReset();
  });

  afterEach(() => {
    cleanup(dir);
  });

  describe('store()', () => {
    it('calls security delete then add with per-key service name', async () => {
      const backend = new MacOSKeychainBackend({ storeDir: dir });

      // delete may throw (not found) — that's ok
      mockExecFileSync.mockImplementation((cmd, args) => {
        if (typeof cmd === 'string' && cmd === 'security' && Array.isArray(args) && args[0] === 'delete-generic-password') {
          throw new Error('not found');
        }
        return Buffer.from('');
      });

      await backend.store('mcp/client/server/KEY', 'secret-value');

      // Verify delete with new service name was attempted
      expect(mockExecFileSync).toHaveBeenCalledWith(
        'security',
        ['delete-generic-password', '-s', 'Secretless: KEY', '-a', 'mcp/client/server/KEY'],
        expect.any(Object),
      );

      // Verify legacy delete was also attempted
      expect(mockExecFileSync).toHaveBeenCalledWith(
        'security',
        ['delete-generic-password', '-s', 'secretless', '-a', 'mcp/client/server/KEY'],
        expect.any(Object),
      );

      // Verify add uses per-key service name
      expect(mockExecFileSync).toHaveBeenCalledWith(
        'security',
        ['add-generic-password', '-s', 'Secretless: KEY', '-a', 'mcp/client/server/KEY', '-l', 'Secretless: mcp/client/server/KEY', '-w', 'secret-value'],
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
    it('deletes both new and legacy entries and removes from index', async () => {
      const backend = new MacOSKeychainBackend({ storeDir: dir });

      // Pre-populate index
      const indexPath = path.join(dir, 'keychain-index.json');
      fs.writeFileSync(indexPath, JSON.stringify(['mcp/client/server/KEY1', 'mcp/client/server/KEY2']));

      mockExecFileSync.mockReturnValue(Buffer.from(''));

      const result = await backend.delete('mcp/client/server/KEY1');
      expect(result).toBe(true);

      // Verify delete with new service name
      expect(mockExecFileSync).toHaveBeenCalledWith(
        'security',
        ['delete-generic-password', '-s', 'Secretless: KEY1', '-a', 'mcp/client/server/KEY1'],
        expect.any(Object),
      );

      // Verify legacy delete also attempted
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

// ─────────────────────────────────────────────────────────────────────────────
// Hex round-trip. `security -w` output is ambiguous between "a hex-looking
// password" and "a password macOS hex-encoded", and the decision used to be
// made from content: decode when the decoded bytes hold a control character.
//
// That silently corrupted most 32-hex API keys. 32 hex chars is 16 random
// bytes, and the control ranges tested cover 32 of 256 values, so
// 1 - (224/256)^16 = 88% of such keys tripped it. The fixture below is the MD5
// of the empty string, an entirely ordinary token, whose bytes include 0x00,
// 0x04 and 0x09.
// ─────────────────────────────────────────────────────────────────────────────

/** Ordinary 32-hex token. Decodes to bytes containing 0x00 / 0x04 / 0x09. */
const HEX32_TOKEN = 'd41d8cd98f00b204e9800998ecf8427e';

describe('decodeKeychainValue', () => {
  it('returns a 32-hex token unchanged when macOS did not encode it', () => {
    // The regression. Against the old content heuristic this returned 16 bytes
    // of binary, so this assertion is red on the pre-fix code.
    const out = decodeKeychainValue(HEX32_TOKEN, () => false);
    expect(out).toBe(HEX32_TOKEN);
    expect(out).toHaveLength(32);
  });

  it('decodes when macOS says it encoded the value', () => {
    // "line1\nline2" is the case the encoding exists for.
    const encoded = Buffer.from('line1\nline2', 'utf-8').toString('hex');
    expect(decodeKeychainValue(encoded, () => true)).toBe('line1\nline2');
  });

  it('fails closed when the encoding cannot be established', () => {
    // No probe available, and a probe that throws, both leave the value alone.
    expect(decodeKeychainValue(HEX32_TOKEN, undefined)).toBe(HEX32_TOKEN);
    expect(
      decodeKeychainValue(HEX32_TOKEN, () => {
        throw new Error('security unavailable');
      }),
    ).toBe(HEX32_TOKEN);
  });

  it('never probes a value that is not shaped like hex output', () => {
    // Odd length, non-hex characters, and empty all skip the extra call.
    const probe = vi.fn(() => true);
    for (const v of ['not-hex-at-all', 'abc', '', 'zzzz']) {
      expect(decodeKeychainValue(v, probe)).toBe(v);
    }
    expect(probe).not.toHaveBeenCalled();
  });
});

describe('keychainOutputIsHexEncoded', () => {
  it('reads the 0x marker on the password line', () => {
    expect(
      keychainOutputIsHexEncoded('password: 0x6C696E65310A6C696E6532  "line1\\012line2"'),
    ).toBe(true);
  });

  it('does not treat a quoted hex-looking password as encoded', () => {
    expect(keychainOutputIsHexEncoded(`password: "${HEX32_TOKEN}"`)).toBe(false);
  });

  it('ignores 0x appearing anywhere but the password line', () => {
    // `-g` also dumps attributes; a 0x in one of them is not the marker.
    const out = [
      'keychain: "/Users/x/Library/Keychains/login.keychain-db"',
      '    "cdat"<timedate>=0x32303236  "20260805"',
      `password: "${HEX32_TOKEN}"`,
    ].join('\n');
    expect(keychainOutputIsHexEncoded(out)).toBe(false);
  });
});

describe('resolve() hex handling', () => {
  it('does not corrupt a stored 32-hex token', async () => {
    const hexDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-keychain-hex-'));
    try {
      const backend = new MacOSKeychainBackend({ storeDir: hexDir });
      fs.writeFileSync(
        path.join(hexDir, 'keychain-index.json'),
        JSON.stringify(['secret/TOKEN']),
      );

      mockExecFileSync.mockReset();
      mockSpawnSync.mockReset();
      mockExecFileSync.mockImplementation((_cmd, args) => {
        if (Array.isArray(args) && args[0] === 'find-generic-password') {
          return HEX32_TOKEN as unknown as Buffer;
        }
        throw new Error('not found');
      });
      // macOS reports it as plain text (quoted, no 0x), so it must not decode.
      mockSpawnSync.mockReturnValue({
        stdout: '',
        stderr: `password: "${HEX32_TOKEN}"`,
      } as unknown as ReturnType<typeof child_process.spawnSync>);

      const out = await backend.resolve('secret/TOKEN');
      expect(out['secret/TOKEN']).toBe(HEX32_TOKEN);
    } finally {
      fs.rmSync(hexDir, { recursive: true, force: true });
    }
  });

  it('decodes a stored value macOS actually hex-encoded', async () => {
    const hexDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-keychain-hex-'));
    try {
      const backend = new MacOSKeychainBackend({ storeDir: hexDir });
      fs.writeFileSync(
        path.join(hexDir, 'keychain-index.json'),
        JSON.stringify(['secret/MULTILINE']),
      );

      const encoded = Buffer.from('line1\nline2', 'utf-8').toString('hex');
      mockExecFileSync.mockReset();
      mockSpawnSync.mockReset();
      mockExecFileSync.mockImplementation((_cmd, args) => {
        if (Array.isArray(args) && args[0] === 'find-generic-password') {
          return encoded as unknown as Buffer;
        }
        throw new Error('not found');
      });
      mockSpawnSync.mockReturnValue({
        stdout: '',
        stderr: `password: 0x${encoded.toUpperCase()}  "line1\\012line2"`,
      } as unknown as ReturnType<typeof child_process.spawnSync>);

      const out = await backend.resolve('secret/MULTILINE');
      expect(out['secret/MULTILINE']).toBe('line1\nline2');
    } finally {
      fs.rmSync(hexDir, { recursive: true, force: true });
    }
  });
});
