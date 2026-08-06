import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { execFileSync } from 'child_process';
import { createBackend, isKeychainAvailable, unavailableBackendError } from './factory';
import { LocalBackend } from './local';

vi.mock('child_process', async (importOriginal) => {
  const actual = await importOriginal<typeof import('child_process')>();
  return { ...actual, execFileSync: vi.fn() };
});

const mockExec = execFileSync as unknown as ReturnType<typeof vi.fn>;

/**
 * Reproduce the machine state that motivated this suite: the `op` BINARY is
 * installed and an account is configured locally, but the 1Password desktop app
 * is not connected, so any command needing the app fails.
 *
 * Measured on a real machine 2026-08-05 (op 2.32.1):
 *   op --version                 -> exit 0
 *   op account list              -> exit 0   (answers from local config)
 *   op account get --format json -> exit 1   (needs the app)
 *   op vault list                -> exit 1
 *
 * The `account list` / `account get` split matters: a probe that used the
 * former would call this machine healthy.
 */
function mockOpInstalledButAppDisconnected(): void {
  mockExec.mockImplementation((cmd: string, args: string[] = []) => {
    if (cmd !== 'op') return '';
    if (args[0] === '--version') return '2.32.1\n';
    if (args[0] === 'account' && args[1] === 'list') return 'my.1password.com\n';
    throw new Error(
      "connecting to desktop app: 1Password CLI couldn't connect to the 1Password desktop app.",
    );
  });
}

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

/**
 * Regression cover for the silent store-substitution bug.
 *
 * Before the fix, an unreachable configured backend returned a LocalBackend and
 * only warned on stderr. `secret set` then wrote to a store the user never
 * chose and printed "Stored: NAME", and `backend purge` would have deleted from
 * that other store. These tests fail on the pre-fix factory, which returned
 * LocalBackend here instead of throwing.
 */
describe('createBackend: unreachable configured backend fails closed', () => {
  beforeEach(() => {
    mockExec.mockReset();
  });

  afterEach(() => {
    delete process.env.VAULT_ADDR;
    delete process.env.VAULT_TOKEN;
  });

  it('throws instead of substituting local when 1Password is unreachable', () => {
    mockOpInstalledButAppDisconnected();
    expect(() => createBackend('1password')).toThrow(/not reachable/i);
  });

  it('never hands back a different store for an unreachable 1Password', () => {
    mockOpInstalledButAppDisconnected();
    let returned: unknown;
    try {
      returned = createBackend('1password');
    } catch {
      returned = undefined;
    }
    // The pre-fix code reached here holding a LocalBackend.
    expect(returned).toBeUndefined();
  });

  it('names the configured backend and gives verify + fix commands, not a dead end', () => {
    mockOpInstalledButAppDisconnected();
    let message = '';
    try {
      createBackend('1password');
    } catch (err) {
      message = (err as Error).message;
    }
    expect(message).toContain('1password');
    expect(message).toMatch(/Verify:\s+op account get/);
    expect(message).toMatch(/Fix:\s+brew install 1password-cli/);
    // The reassurance is load-bearing: this fires while a user is mid-command.
    expect(message).toMatch(/secrets are safe/i);
    // It must NOT claim it used another store.
    expect(message).not.toMatch(/using local backend instead/i);
  });

  it('throws for an unconfigured Vault backend rather than substituting local', () => {
    expect(() => createBackend('vault')).toThrow(/not reachable/i);
  });

  it('builds the Vault backend once its environment is present', () => {
    process.env.VAULT_ADDR = 'https://vault.example.com';
    process.env.VAULT_TOKEN = 'test-token';
    expect(() => createBackend('vault')).not.toThrow();
  });

  it('still degrades for read-only diagnostics that opt in explicitly', () => {
    mockOpInstalledButAppDisconnected();
    const scratch = tmpDir();
    try {
      const backend = createBackend('1password', { storeDir: scratch, key: 'test' }, false);
      expect(backend).toBeInstanceOf(LocalBackend);
    } finally {
      cleanup(scratch);
    }
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

describe('unavailableBackendError formatting', () => {
  it('keeps the Verify/Fix block intact when the reason carries newlines', () => {
    const err = unavailableBackendError(
      '1password',
      'line one\nline two\n  indented three',
      ['do the thing'],
      'op account get',
    );
    const lines = err.message.split('\n');
    // The reason must occupy exactly one line, or everything below it stops
    // reading as a list.
    expect(lines[0]).toBe(
      'Configured backend "1password" is not reachable: line one line two indented three',
    );
    expect(err.message).toMatch(/^  Verify:  op account get$/m);
    expect(err.message).toMatch(/^  Fix:     do the thing$/m);
  });
});
