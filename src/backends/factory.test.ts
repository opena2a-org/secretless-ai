import { describe, it, expect, vi, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { createBackend, isKeychainAvailable } from './factory';
import { LocalBackend } from './local';

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-factory-test-'));
}

function cleanup(dir: string): void {
  fs.rmSync(dir, { recursive: true, force: true });
}

describe('createBackend', () => {
  let dir: string;

  afterEach(() => {
    if (dir) cleanup(dir);
  });

  it('creates LocalBackend for "local" type', () => {
    dir = tmpDir();
    const backend = createBackend('local', { storeDir: dir, key: 'test' });
    expect(backend.name).toBe('local');
    expect(backend).toBeInstanceOf(LocalBackend);
  });

  it('creates a keychain backend for "keychain" type', () => {
    dir = tmpDir();
    const backend = createBackend('keychain', { storeDir: dir });
    // On macOS it should be keychain-macos, on Linux keychain-linux
    // On other platforms it falls back to local
    // With default cache TTL > 0, keychain backends get wrapped in CachedBackend
    const validNames = [
      'keychain-macos', 'keychain-linux', 'local',
      'cached(keychain-macos)', 'cached(keychain-linux)', 'cached(local)',
    ];
    expect(validNames).toContain(backend.name);
  });
});

describe('isKeychainAvailable', () => {
  it('returns platform information', () => {
    const result = isKeychainAvailable();
    expect(result).toHaveProperty('available');
    expect(result).toHaveProperty('platform');
    expect(result).toHaveProperty('message');
    expect(typeof result.available).toBe('boolean');
    expect(typeof result.platform).toBe('string');
    expect(typeof result.message).toBe('string');
  });

  it('returns correct platform name', () => {
    const result = isKeychainAvailable();
    if (process.platform === 'darwin') {
      expect(result.platform).toBe('macOS');
    } else if (process.platform === 'linux') {
      expect(result.platform).toBe('Linux');
    }
  });
});
