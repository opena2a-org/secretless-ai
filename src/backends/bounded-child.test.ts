import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { EventEmitter } from 'events';
import { PassThrough } from 'stream';
import { spawn, execFileSync, type ChildProcess } from 'child_process';
import {
  OS_KEYCHAIN_SWITCH,
  execFileSyncBounded,
  osKeychainRefused,
  runBoundedChild,
} from './bounded-child';
import { MacOSKeychainBackend } from './keychain-macos';
import { LinuxKeychainBackend } from './keychain-linux';
import { makeMarkerProgram, withPathPrefix, withPlatform } from './child-recorder.test-support';

/**
 * `child_process` is wrapped, not replaced: every call goes to the real
 * function unless a cell queues a stand-in, so the backend cells below run
 * their real child path. The OS credential-store programs are fenced in the
 * wrapper: if the switch ever stops refusing them, the call fails here with a
 * message that does not name the switch, instead of reaching a store.
 */
vi.mock('child_process', async (importOriginal) => {
  const actual = await importOriginal<typeof import('child_process')>();
  const fence = (program: unknown, args: unknown) => {
    const argv = Array.isArray(args) ? args : [];
    if (program === '/usr/bin/security' || program === 'secret-tool' || (program === 'which' && argv[0] === 'secret-tool')) {
      throw new Error(`test fence: ${String(program)} reached child_process`);
    }
  };
  return {
    ...actual,
    spawn: vi.fn((program: string, args: readonly string[], opts: object) => {
      fence(program, args);
      return actual.spawn(program, args, opts);
    }),
    execFileSync: vi.fn((program: string, args: readonly string[], opts: object) => {
      fence(program, args);
      return actual.execFileSync(program, args, opts);
    }),
  };
});

const spawnMock = vi.mocked(spawn);
const execFileSyncMock = vi.mocked(execFileSync);

const REFUSAL = /SECRETLESS_OS_KEYCHAIN/;

/** A child that has already run and exits with `status`; nothing is started. */
function exitedChild(status: number): ChildProcess {
  const child = Object.assign(new EventEmitter(), {
    stdout: new PassThrough(),
    stderr: new PassThrough(),
    stdin: new PassThrough(),
    pid: 4242,
    killed: false,
  });
  setImmediate(() => child.emit('close', status, null));
  return child as unknown as ChildProcess;
}

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-bounded-child-test-'));
}

/** Run `fn` with the switch set to `value` (undefined: unset), restoring `off` after. */
async function withSwitch<T>(value: string | undefined, fn: () => Promise<T> | T): Promise<T> {
  if (value === undefined) delete process.env.SECRETLESS_OS_KEYCHAIN;
  else process.env.SECRETLESS_OS_KEYCHAIN = value;
  try {
    return await fn();
  } finally {
    process.env.SECRETLESS_OS_KEYCHAIN = 'off';
  }
}

beforeEach(() => {
  spawnMock.mockClear();
  execFileSyncMock.mockClear();
});

describe('precondition: the suite refuses the OS credential-store CLIs', () => {
  it('SECRETLESS_OS_KEYCHAIN is "off" in this worker; if this fails, vitest.config.ts lost its test.env line and tests can reach the real Keychain', () => {
    expect(OS_KEYCHAIN_SWITCH).toBe('SECRETLESS_OS_KEYCHAIN');
    expect(process.env.SECRETLESS_OS_KEYCHAIN).toBe('off');
  });
});

describe('SECRETLESS_OS_KEYCHAIN=off: refused at the chokepoint, before any child starts', () => {
  const refused: Array<[string, string[]]> = [
    ['/usr/bin/security', ['default-keychain']],
    ['secret-tool', ['lookup', 'service', 'secretless', 'account', 'K']],
    ['which', ['secret-tool']],
  ];

  it.each(refused)('runBoundedChild(%s) rejects naming the variable, and spawn is never called', async (program, args) => {
    let pending: Promise<unknown> | undefined;
    // A rejection, not a synchronous throw: every caller awaits the result.
    expect(() => { pending = runBoundedChild(program, args, { timeoutMs: 1000 }); }).not.toThrow();
    await expect(pending).rejects.toThrow(REFUSAL);
    expect(spawnMock).not.toHaveBeenCalled();
  });

  it.each(refused)('execFileSyncBounded(%s) throws naming the variable, and execFileSync is never called', (program, args) => {
    expect(() => execFileSyncBounded(program, args, 1000)).toThrow(REFUSAL);
    expect(execFileSyncMock).not.toHaveBeenCalled();
  });

  it('the refusal says nothing was read or written, and its only Fix is to unset the variable', async () => {
    const err: Error = await runBoundedChild('/usr/bin/security', ['default-keychain'], { timeoutMs: 1000 })
      .then(() => { throw new Error('expected a rejection'); }, (e: Error) => e);
    expect(err.message).toContain('/usr/bin/security was not started: SECRETLESS_OS_KEYCHAIN=off is set in this process.');
    expect(err.message).toContain('Nothing was read from or written to any store.');
    expect(err.message).toContain('Verify:  printenv SECRETLESS_OS_KEYCHAIN');
    expect(err.message).toContain('Fix:     unset SECRETLESS_OS_KEYCHAIN');
    // It must not point the user at a weaker store.
    expect(err.message).not.toMatch(/backend|local|\.env|export /i);
  });
});

describe('SECRETLESS_OS_KEYCHAIN: exact match only', () => {
  const lookalike = path.join(os.tmpdir(), 'secretless-not-the-keychain', 'security');
  const reached: Array<[string, string[]]> = [
    [lookalike, ['default-keychain']],
    ['op', ['--version']],
    ['which', ['op']],
  ];

  it.each(reached)('runBoundedChild(%s) is not refused: it reaches spawn with that program', async (program, args) => {
    spawnMock.mockImplementationOnce(() => exitedChild(0));
    const res = await runBoundedChild(program, args, { timeoutMs: 1000 });
    expect(res.status).toBe(0);
    expect(spawnMock).toHaveBeenCalledTimes(1);
    expect(spawnMock.mock.calls[0][0]).toBe(program);
    expect(spawnMock.mock.calls[0][1]).toEqual(args);
  });

  it.each(reached)('execFileSyncBounded(%s) is not refused: it reaches execFileSync with that program', (program, args) => {
    execFileSyncMock.mockImplementationOnce(() => Buffer.from(''));
    expect(() => execFileSyncBounded(program, args, 1000)).not.toThrow();
    expect(execFileSyncMock).toHaveBeenCalledTimes(1);
    expect(execFileSyncMock.mock.calls[0][0]).toBe(program);
  });

  it.each([['1'], ['true'], ['OFF'], [''], [undefined]])('the value %j does not refuse: /usr/bin/security reaches spawn and execFileSync', async (value) => {
    await withSwitch(value, async () => {
      expect(osKeychainRefused('/usr/bin/security', ['default-keychain'])).toBe(false);
      expect(osKeychainRefused('which', ['secret-tool'])).toBe(false);

      // Stand-ins only: no real child starts in this cell.
      spawnMock.mockImplementationOnce(() => exitedChild(0));
      const res = await runBoundedChild('/usr/bin/security', ['default-keychain'], { timeoutMs: 1000 });
      expect(res.status).toBe(0);
      expect(spawnMock).toHaveBeenCalledTimes(1);
      expect(spawnMock.mock.calls[0][0]).toBe('/usr/bin/security');

      execFileSyncMock.mockImplementationOnce(() => Buffer.from(''));
      execFileSyncBounded('/usr/bin/security', ['default-keychain'], 1000);
      expect(execFileSyncMock).toHaveBeenCalledTimes(1);
      expect(execFileSyncMock.mock.calls[0][0]).toBe('/usr/bin/security');
    });
    expect(process.env.SECRETLESS_OS_KEYCHAIN).toBe('off');
  });
});

describe('SECRETLESS_OS_KEYCHAIN=off: every backend operation fails closed, and nothing starts', () => {
  it('MacOSKeychainBackend: store, resolve, delete and healthCheck each reject; no security child starts; the index is untouched', async () => {
    const planted = makeMarkerProgram('security');
    const dir = tmpDir();
    try {
      // Positive control: the planted program does run when started, so
      // "never ran" below is a finding and not a broken fixture.
      expect(planted.controlRun()).toBe(true);
      expect(planted.ran()).toBe(false);

      const indexPath = path.join(dir, 'keychain-index.json');
      fs.writeFileSync(indexPath, JSON.stringify(['secret/K']));
      const backend = new MacOSKeychainBackend({ storeDir: dir });

      await withPathPrefix(planted.dir, async () => {
        const stored = await backend.store('secret/K', 'value-one').then(() => null, (e: Error) => e);
        expect(stored?.message).toMatch(REFUSAL);
        expect(stored?.message).not.toContain('value-one');
        await expect(backend.resolve('secret/K')).rejects.toThrow(REFUSAL);
        await expect(backend.delete('secret/K')).rejects.toThrow(REFUSAL);
        await expect(backend.healthCheck()).rejects.toThrow(REFUSAL);
      });

      expect(planted.ran()).toBe(false);
      expect(spawnMock).not.toHaveBeenCalled();
      expect(JSON.parse(fs.readFileSync(indexPath, 'utf-8'))).toEqual(['secret/K']);
    } finally {
      planted.cleanup();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('LinuxKeychainBackend: store, delete and healthCheck reject, and resolve rejects rather than returning {}; no secret-tool or which child starts', async () => {
    const plantedTool = makeMarkerProgram('secret-tool');
    const plantedWhich = makeMarkerProgram('which');
    const dir = tmpDir();
    try {
      expect(plantedTool.controlRun()).toBe(true);
      expect(plantedWhich.controlRun()).toBe(true);
      expect(plantedTool.ran()).toBe(false);
      expect(plantedWhich.ran()).toBe(false);

      const indexPath = path.join(dir, 'keychain-index.json');
      fs.writeFileSync(indexPath, JSON.stringify(['secret/K']));

      await withPlatform('linux', () =>
        withPathPrefix(plantedTool.dir, () =>
          withPathPrefix(plantedWhich.dir, async () => {
            const backend = new LinuxKeychainBackend({ storeDir: dir });
            const stored = await backend.store('secret/K', 'value-one').then(() => null, (e: Error) => e);
            expect(stored?.message).toMatch(REFUSAL);
            expect(stored?.message).not.toContain('value-one');
            await expect(backend.resolve('secret/K')).rejects.toThrow(REFUSAL);
            await expect(backend.delete('secret/K')).rejects.toThrow(REFUSAL);
            await expect(backend.healthCheck()).rejects.toThrow(REFUSAL);
          })));

      expect(plantedTool.ran()).toBe(false);
      expect(plantedWhich.ran()).toBe(false);
      expect(spawnMock).not.toHaveBeenCalled();
      expect(JSON.parse(fs.readFileSync(indexPath, 'utf-8'))).toEqual(['secret/K']);
    } finally {
      plantedTool.cleanup();
      plantedWhich.cleanup();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
