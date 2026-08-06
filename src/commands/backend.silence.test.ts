import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

// Regression guard for the 0.16.2 fix: read-only command paths must NOT shell
// out to `security` (Touch ID on macOS) or `op` (the "1Password Access
// Requested" dialog on Macs with the desktop app). If a future change pushes
// an active probe back onto a silent path, these tests catch it before users do.

const execFileMock = vi.fn();
const execMock = vi.fn();
const spawnSyncMock = vi.fn();

vi.mock('child_process', async (importOriginal) => {
  const actual = await importOriginal<typeof import('child_process')>();
  return {
    ...actual,
    execFileSync: (...args: unknown[]) => {
      execFileMock(...args);
      const cmd = args[0] as string;
      // Anything that's not security/op falls through to real implementation
      // so unrelated commands (e.g. git in scan-staged) keep working.
      if (cmd === 'security' || cmd === 'op' || cmd === 'which') {
        // Simulate "not present" rather than actually shelling out — keeps the
        // test deterministic on dev machines where these binaries exist.
        const err = new Error(`mocked: ${cmd} not invoked in tests`);
        throw err;
      }
      return actual.execFileSync(...(args as Parameters<typeof actual.execFileSync>));
    },
    execSync: (...args: unknown[]) => {
      execMock(...args);
      return actual.execSync(...(args as Parameters<typeof actual.execSync>));
    },
    spawnSync: (...args: unknown[]) => {
      spawnSyncMock(...args);
      return actual.spawnSync(...(args as Parameters<typeof actual.spawnSync>));
    },
  };
});

function makeFakeHome(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-silence-test-'));
}

function cleanup(dir: string): void {
  fs.rmSync(dir, { recursive: true, force: true });
}

describe('read-only commands stay silent (no biometric / 1P prompts)', () => {
  let originalHome: string | undefined;
  let originalLog: typeof console.log;
  let originalError: typeof console.error;
  let fakeHome: string;

  beforeEach(() => {
    fakeHome = makeFakeHome();
    originalHome = process.env.HOME;
    process.env.HOME = fakeHome;

    originalLog = console.log;
    originalError = console.error;
    console.log = () => {};
    console.error = () => {};

    execFileMock.mockClear();
    execMock.mockClear();
    spawnSyncMock.mockClear();
  });

  afterEach(() => {
    console.log = originalLog;
    console.error = originalError;
    if (originalHome !== undefined) {
      process.env.HOME = originalHome;
    } else {
      delete process.env.HOME;
    }
    cleanup(fakeHome);
  });

  function offending(): unknown[][] {
    return [
      ...execFileMock.mock.calls.filter(([cmd]) => cmd === 'security' || cmd === 'op'),
      ...execMock.mock.calls.filter(([cmd]) => typeof cmd === 'string' && (cmd.includes('security ') || cmd.startsWith('op '))),
      ...spawnSyncMock.mock.calls.filter(([cmd]) => cmd === 'security' || cmd === 'op'),
    ];
  }

  it('runBackend with no subcommand does not invoke `security` or `op`', async () => {
    const { runBackend } = await import('./backend');
    const exitCode = await runBackend([]);
    expect(exitCode).toBe(0);
    expect(offending()).toEqual([]);
  });

  it('runStatus does not invoke `security` or `op`', async () => {
    const { runStatus } = await import('./core');
    const exitCode = runStatus(fakeHome);
    expect(exitCode).toBe(0);
    expect(offending()).toEqual([]);
  });

  it('createBackend("local") does not invoke `security` (keychain upgrade uses Likely probe)', async () => {
    // No `key` in config — exercises the local→keychain upgrade branch in
    // factory.ts, which is the path that used to fire `security default-keychain`
    // and could trigger Touch ID on macOS.
    const { createBackend } = await import('../backends/factory');
    createBackend('local', { storeDir: fakeHome });
    expect(offending()).toEqual([]);
  });
});

// Re-test P2: `cache` keyed its auth-prompt advice off the CONFIGURED backend,
// so on a default machine it said "Not needed (local backend has no auth
// prompts)" while secrets were going to the Keychain, which does prompt.
describe('cache reports the effective backend', () => {
  it('names the same backend `backend` and SecretStore report', async () => {
    const { runCache } = await import('./backend');
    const { effectiveBackendName } = await import('../backends/factory');
    const { resolveBackendType } = await import('../backends/config');

    const out: string[] = [];
    const spy = vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { out.push(a.join(' ')); });
    try {
      await runCache([]);
    } finally {
      spy.mockRestore();
    }

    const expected = effectiveBackendName(resolveBackendType());
    const backendLine = out.find(l => l.includes('Backend:')) ?? '';
    expect(backendLine).toContain(expected);

    // And the advice must follow from the EFFECTIVE backend, not the config.
    const statusLine = out.find(l => l.includes('Status:')) ?? '';
    if (expected.startsWith('keychain') || expected === '1password') {
      expect(statusLine).not.toContain('no auth prompts');
    }
  });
});
