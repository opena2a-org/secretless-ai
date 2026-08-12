import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as child_process from 'child_process';
import {
  MacOSKeychainBackend,
  decodeKeychainValue,
  keychainOutputIsHexEncoded,
  redactSecurityError,
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
    it('writes with an in-place update and sweeps the legacy entry after', async () => {
      const backend = new MacOSKeychainBackend({ storeDir: dir });

      // legacy delete may throw (not found) — that's ok
      mockExecFileSync.mockImplementation((cmd, args) => {
        if (typeof cmd === 'string' && cmd === 'security' && Array.isArray(args) && args[0] === 'delete-generic-password') {
          throw new Error('not found');
        }
        return Buffer.from('');
      });

      await backend.store('mcp/client/server/KEY', 'secret-value');

      // `-U` updates in place, so no delete of the live entry precedes the
      // write. The previous ordering deleted first and lost the credential
      // outright whenever the add then failed.
      expect(mockExecFileSync).toHaveBeenCalledWith(
        'security',
        ['add-generic-password', '-s', 'Secretless: KEY', '-a', 'mcp/client/server/KEY', '-l', 'Secretless: mcp/client/server/KEY', '-U', '-w', 'secret-value'],
        expect.any(Object),
      );

      // The live entry is never deleted as part of a write.
      expect(mockExecFileSync).not.toHaveBeenCalledWith(
        'security',
        ['delete-generic-password', '-s', 'Secretless: KEY', '-a', 'mcp/client/server/KEY'],
        expect.any(Object),
      );

      // The legacy duplicate is still swept, after the value is committed.
      expect(mockExecFileSync).toHaveBeenCalledWith(
        'security',
        ['delete-generic-password', '-s', 'secretless', '-a', 'mcp/client/server/KEY'],
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

    it('skips keys the Keychain says are absent', async () => {
      const backend = new MacOSKeychainBackend({ storeDir: dir });

      const indexPath = path.join(dir, 'keychain-index.json');
      fs.writeFileSync(indexPath, JSON.stringify(['mcp/client/server/KEY1']));

      // 44 is what `security` exits with for "The specified item could not be
      // found in the keychain". This one really is absent.
      mockExecFileSync.mockImplementation(() => {
        throw Object.assign(new Error('item could not be found'), { status: 44 });
      });

      const result = await backend.resolve('mcp/client/server');
      expect(result).toEqual({});
    });

    it('refuses to report a key absent when the Keychain would not answer', async () => {
      // This test replaces one titled "skips keys that fail to retrieve", which
      // asserted {} for ANY failure — the fail-open in #104 written down as the
      // expected behaviour. A locked Keychain, or a dismissed approval dialog,
      // made every secret read as missing with exit 0.
      const backend = new MacOSKeychainBackend({ storeDir: dir });

      const indexPath = path.join(dir, 'keychain-index.json');
      fs.writeFileSync(indexPath, JSON.stringify(['mcp/client/server/KEY1']));

      mockExecFileSync.mockImplementation(() => {
        throw Object.assign(
          new Error('User interaction is not allowed'),
          { status: 51 },
        );
      });

      await expect(backend.resolve('mcp/client/server')).rejects.toThrow(
        /would not return "mcp\/client\/server\/KEY1"/,
      );
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

  it('refuses when the encoding cannot be established', () => {
    // This test used to be called "fails closed" and asserted the raw value was
    // returned. Returning the raw value is not failing closed, it is answering
    // "not encoded" to a question nobody answered — and when the value IS
    // encoded, that answer hands back the hex transcript of the credential
    // instead of the credential.
    expect(() => decodeKeychainValue(HEX32_TOKEN, () => null, 'secret/K'))
      .toThrow(/Could not determine how the macOS Keychain stored "secret\/K"/);
    expect(() =>
      decodeKeychainValue(HEX32_TOKEN, () => {
        throw new Error('security unavailable');
      }, 'secret/K'),
    ).toThrow(/Could not determine/);
  });

  it('does not refuse a value that is not shaped like hex, even when unanswered', () => {
    // The other direction: an unanswered probe only matters for a value the
    // probe would have been asked about. Refusing more widely would turn every
    // read on a locked Keychain into a failure for no gain.
    expect(decodeKeychainValue('not-hex-at-all', () => null, 'secret/K'))
      .toBe('not-hex-at-all');
  });

  it('never puts the value in the refusal', () => {
    try {
      decodeKeychainValue(HEX32_TOKEN, () => null, 'secret/K');
      throw new Error('expected decodeKeychainValue to throw');
    } catch (err) {
      const message = (err as Error).message;
      for (let i = 0; i + 4 <= HEX32_TOKEN.length; i++) {
        expect(message).not.toContain(HEX32_TOKEN.slice(i, i + 4));
      }
    }
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
        // A real successful spawnSync sets status 0. The mock omitted it, and a
        // probe that cannot report success is a probe that did not complete.
        status: 0,
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
        // A real successful spawnSync sets status 0. The mock omitted it, and a
        // probe that cannot report success is a probe that did not complete.
        status: 0,
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

/**
 * `security add-generic-password` takes the password as `-w <value>`, and
 * execFileSync puts the whole argv into the thrown message. Observed in a fresh
 * -user walkthrough of 0.21.0-rc:
 *
 *   Error: Command failed: security add-generic-password -s Secretless: NUTEST \
 *     -a secret/NUTEST -l Secretless: secret/NUTEST -w hello-world-123
 *
 * The secret is right there in the terminal, in a tool whose whole purpose is
 * keeping it out of exactly that kind of output.
 */
describe('store() error redaction', () => {
  const SECRET = 'hello-world-123';

  it('does not leak the value through the thrown error', () => {
    const err = redactSecurityError(
      new Error(
        'Command failed: security add-generic-password -s Secretless: NUTEST ' +
        `-a secret/NUTEST -w ${SECRET}\n` +
        'security: SecKeychainItemCreateFromContent (<default>): The authorization was canceled by the user.',
      ),
      SECRET,
      'secret/NUTEST',
    );
    expect(err.message).not.toContain(SECRET);
  });

  it('drops our own argv echo and keeps the part that explains the failure', () => {
    const err = redactSecurityError(
      new Error(`Command failed: security add-generic-password -w ${SECRET}\nsecurity: the thing broke`),
      SECRET,
      'secret/K',
    );
    expect(err.message).not.toMatch(/Command failed:/);
    expect(err.message).toContain('the thing broke');
    expect(err.message).toContain('secret/K');
  });

  it('routes the locked-keychain case to advice the user can act on', () => {
    const err = redactSecurityError(
      new Error('security: The authorization was canceled by the user.'),
      SECRET,
      'secret/K',
    );
    expect(err.message).toMatch(/Verify:\s+security default-keychain/);
    expect(err.message).toMatch(/backend set local/);
  });

  it('discards the detail rather than leaking when scrubbing cannot clear it', () => {
    // A value that survives naive scrubbing because it reappears after
    // replacement: splitting on "aa" in "aaa" leaves an "a" behind.
    const tricky = 'aa';
    const err = redactSecurityError(new Error('security: aaaaa failed'), tricky, 'secret/K');
    expect(err.message).not.toContain(tricky);
  });

  it('is actually wired into store(), not merely exported', async () => {
    const dir2 = tmpDir();
    try {
      mockExecFileSync.mockImplementation(((_cmd: string, args: string[]) => {
        if (Array.isArray(args) && args[0] === 'add-generic-password') {
          throw new Error(
            `Command failed: security add-generic-password -w ${SECRET}\n` +
            'security: The authorization was canceled by the user.',
          );
        }
        return '' as unknown as Buffer;
      }) as never);

      const backend = new MacOSKeychainBackend({ storeDir: dir2 });
      await expect(backend.store('secret/NUTEST', SECRET)).rejects.toThrow(
        /Could not store "secret\/NUTEST"/,
      );
      await backend.store('secret/NUTEST', SECRET).catch((e: Error) => {
        expect(e.message).not.toContain(SECRET);
      });
    } finally {
      cleanup(dir2);
    }
  });

  it('updates in place instead of deleting the old value before writing', async () => {
    const dir2 = tmpDir();
    try {
      const calls: string[] = [];
      mockExecFileSync.mockImplementation(((_cmd: string, args: string[]) => {
        if (Array.isArray(args)) calls.push(args[0]);
        return '' as unknown as Buffer;
      }) as never);

      const backend = new MacOSKeychainBackend({ storeDir: dir2 });
      await backend.store('secret/K', 'v');

      const addIdx = calls.indexOf('add-generic-password');
      const delIdx = calls.indexOf('delete-generic-password');
      expect(addIdx).toBeGreaterThanOrEqual(0);
      // No delete may precede the write; the legacy sweep runs after it.
      if (delIdx !== -1) expect(addIdx).toBeLessThan(delIdx);
    } finally {
      cleanup(dir2);
    }
  });
});

/**
 * Adversarial cases for the redaction, found by probing it rather than by
 * reading it. A secret may legitimately contain newlines — that is why the
 * read path handles hex-encoded values at all.
 */
describe('store() error redaction: adversarial inputs', () => {
  it('does not leak a fragment when the value straddles the filtered line', () => {
    // Scrubbing after the "Command failed:" line filter split this value in
    // two, so neither the replace nor the containment check could see it and
    // "realsecret" survived into the message.
    const value = 'Command failed: X\nrealsecret';
    const err = redactSecurityError(
      new Error(`Command failed: security add-generic-password -w ${value}`),
      value,
      'secret/K',
    );
    expect(err.message).not.toContain('realsecret');
    expect(err.message).not.toContain(value);
  });

  it('does not leak any line of a multi-line secret echoed back mangled', () => {
    const value = '-----BEGIN KEY-----\nMIIEvgIBADANBg\n-----END KEY-----';
    // security echoes only the middle line back, so the whole-value check misses it.
    const err = redactSecurityError(
      new Error('security: could not store MIIEvgIBADANBg'),
      value,
      'secret/K',
    );
    expect(err.message).not.toContain('MIIEvgIBADANBg');
  });

  it('survives a value that is itself the redaction placeholder', () => {
    const value = '[REDACTED]';
    const err = redactSecurityError(new Error('security: [REDACTED] failed'), value, 'secret/K');
    // Cannot distinguish placeholder from secret, so the detail is dropped.
    expect(err.message).toContain('Could not store');
  });

  it('still produces an actionable message when the detail is discarded', () => {
    const err = redactSecurityError(new Error('security: aaaaa'), 'aa', 'secret/K');
    expect(err.message).toMatch(/Verify:/);
    expect(err.message).toMatch(/Fix:/);
  });
});
