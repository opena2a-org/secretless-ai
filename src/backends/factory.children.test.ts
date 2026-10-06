import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { spawn } from 'child_process';
import { isKeychainAvailable } from './factory';
import {
  makeHangingProgram,
  makeMarkerProgram,
  processIsGone,
  withPathPrefix,
  withPlatform,
  writeProgram,
} from './child-recorder.test-support';

/**
 * The factory's availability probes start real children. factory.test.ts
 * replaces `child_process` with a mock, so the children themselves are
 * observed here, in a file with no mock.
 */

describe('factory probes: program custody', () => {
  it('SLS-10.AC2 isKeychainAvailable on darwin runs /usr/bin/security by absolute path: a security planted first on PATH never runs', async () => {
    const planted = makeMarkerProgram('security');
    try {
      // Positive control: the planted program does run when started.
      expect(planted.controlRun()).toBe(true);
      expect(planted.ran()).toBe(false);

      const result = await withPlatform('darwin', () =>
        withPathPrefix(planted.dir, () => isKeychainAvailable()));
      expect(planted.ran()).toBe(false);
      expect(result.platform).toBe('macOS');
      // The suite runs with SECRETLESS_OS_KEYCHAIN=off (vitest.config.ts):
      // /usr/bin/security is refused before it starts, on every host, so the
      // probe says not available, and says why. PATH had no part in the answer.
      expect(result.available).toBe(false);
      expect(result.message).toContain('/usr/bin/security was not started: SECRETLESS_OS_KEYCHAIN=off');
    } finally {
      planted.cleanup();
    }
  });
});

/**
 * `backend set keychain` prints the probe's message as its reason. Under the
 * switch that message is the refusal itself: a generic "not accessible" or
 * "not found" would hide the variable, and its Verify and Fix lines, from the
 * one person who can unset it (#205).
 */
describe('factory probes: the OS keychain refusal is the reported reason', () => {
  const SWITCH_LINES = [
    'SECRETLESS_OS_KEYCHAIN=off is set in this process.',
    'Verify:  printenv SECRETLESS_OS_KEYCHAIN',
    'Fix:     unset SECRETLESS_OS_KEYCHAIN',
  ];

  it('isKeychainAvailable on darwin carries the refusal, Verify and Fix lines included, as its message', async () => {
    expect(process.env.SECRETLESS_OS_KEYCHAIN, 'vitest.config.ts sets the switch').toBe('off');
    const result = await withPlatform('darwin', () => isKeychainAvailable());
    expect(result).toMatchObject({ available: false, platform: 'macOS' });
    for (const line of SWITCH_LINES) expect(result.message).toContain(line);
    expect(result.message).not.toContain('not accessible');
  });

  it('isKeychainAvailable on linux carries the refusal of `which secret-tool`, not "secret-tool not found"', async () => {
    const result = await withPlatform('linux', () => isKeychainAvailable());
    expect(result).toMatchObject({ available: false, platform: 'Linux' });
    for (const line of SWITCH_LINES) expect(result.message).toContain(line);
    expect(result.message).not.toContain('not found');
  });

  it('CONTROL: on linux without the switch the probe runs and its message never names the switch', async () => {
    // `which` is not an OS credential-store CLI; with the switch unset it runs
    // and answers from PATH, so nothing here can reach a store.
    const saved = process.env.SECRETLESS_OS_KEYCHAIN;
    delete process.env.SECRETLESS_OS_KEYCHAIN;
    try {
      const result = await withPlatform('linux', () => isKeychainAvailable());
      expect(result.platform).toBe('Linux');
      expect(result.message).not.toContain('SECRETLESS_OS_KEYCHAIN');
    } finally {
      if (saved === undefined) delete process.env.SECRETLESS_OS_KEYCHAIN;
      else process.env.SECRETLESS_OS_KEYCHAIN = saved;
    }
  });
});

/**
 * The probes are synchronous, so a hang inside one blocks this very event
 * loop, and a test timeout could never fire. The cell therefore runs the
 * probe in a child node process, from the built `dist/`, and this process
 * holds the outer deadline: a probe that never returns is killed and read as
 * a failure.
 */
describe('factory probes: every child call is bounded', () => {
  const DIST_FACTORY = path.resolve(process.cwd(), 'dist/backends/factory.js');
  const OUTER_DEADLINE_MS = 15_000;

  interface Outcome {
    status: number | null;
    signal: NodeJS.Signals | null;
    stdout: string;
    stderr: string;
  }

  function runProbeInChild(
    fn: 'isKeychainAvailable' | 'isOnePasswordAvailable',
    platform: NodeJS.Platform,
    pathPrefix: string,
    childTimeoutMs: number,
    env: NodeJS.ProcessEnv = process.env,
  ): Promise<Outcome> {
    if (!fs.existsSync(DIST_FACTORY)) {
      throw new Error(`${DIST_FACTORY} is missing; run \`npm run build\` before this suite`);
    }
    // Under node_modules/.cache, like the recorders: see makeDir() in
    // child-recorder.test-support.ts for why not os.tmpdir().
    const base = path.resolve(process.cwd(), 'node_modules', '.cache', 'secretless-child-recorders');
    fs.mkdirSync(base, { recursive: true });
    const dir = fs.mkdtempSync(path.join(base, 'probe-harness-'));
    const harness = writeProgram(dir, 'harness.js', `
const path = require('path');
const [dist, fn, platform, prefix, ms] = process.argv.slice(2);
process.env.PATH = prefix + path.delimiter + (process.env.PATH || '');
Object.defineProperty(process, 'platform', { value: platform, configurable: true });
const factory = require(dist);
const start = Date.now();
const result = factory[fn]({ childTimeoutMs: Number(ms) });
process.stdout.write(JSON.stringify({ result, elapsedMs: Date.now() - start, osKeychainSwitch: process.env.SECRETLESS_OS_KEYCHAIN ?? null }));
`);
    return new Promise((resolve) => {
      const child = spawn(
        process.execPath,
        [harness, DIST_FACTORY, fn, platform, pathPrefix, String(childTimeoutMs)],
        { stdio: ['ignore', 'pipe', 'pipe'], timeout: OUTER_DEADLINE_MS, killSignal: 'SIGKILL', env },
      );
      let stdout = '';
      let stderr = '';
      child.stdout.setEncoding('utf-8');
      child.stdout.on('data', (d: string) => { stdout += d; });
      child.stderr.setEncoding('utf-8');
      child.stderr.on('data', (d: string) => { stderr += d; });
      child.on('close', (status, signal) => {
        fs.rmSync(dir, { recursive: true, force: true });
        resolve({ status, signal, stdout, stderr });
      });
    });
  }

  it('SLS-10.AC4 isKeychainAvailable on linux: a which that never exits returns "not available" within the bound and the child is gone', { timeout: OUTER_DEADLINE_MS + 5_000 }, async () => {
    const hanging = makeHangingProgram('which');
    try {
      // Positive control, and the program's first start paid outside the bound.
      expect(hanging.controlRun()).toBe(true);
      expect(hanging.pid()).toBeNull();
      // SECRETLESS_OS_KEYCHAIN=off would refuse `which secret-tool` before it
      // starts, and this cell needs the child to start. It is removed for this
      // one harness only: its platform is forced to linux, so the probe's only
      // child is `which secret-tool`, which resolves to the hanging `which`
      // first on PATH. No keychain CLI is reachable from it.
      const { SECRETLESS_OS_KEYCHAIN: _off, ...withoutSwitch } = process.env;
      const out = await runProbeInChild('isKeychainAvailable', 'linux', hanging.dir, 500, withoutSwitch);
      expect(out.signal, `probe did not return before the outer deadline\n${out.stderr}`).toBeNull();
      expect(out.status, out.stderr).toBe(0);
      const { result, elapsedMs, osKeychainSwitch } = JSON.parse(out.stdout);
      expect(osKeychainSwitch).toBeNull();
      expect(result.available).toBe(false);
      expect(result.platform).toBe('Linux');
      expect(elapsedMs).toBeLessThan(5_000);
      const pid = hanging.pid();
      expect(pid, `the hanging which left no pid; probe elapsed ${elapsedMs}ms\n${out.stderr}`).not.toBeNull();
      expect(processIsGone(pid!)).toBe(true);
    } finally {
      hanging.cleanup();
    }
  });

  it('SLS-10.AC4 isOnePasswordAvailable: an op that never exits returns "not available" within the bound and the child is gone', { timeout: OUTER_DEADLINE_MS + 5_000 }, async () => {
    const hanging = makeHangingProgram('op');
    try {
      // Positive control, and the program's first start paid outside the bound.
      // `op` is not an OS credential-store CLI, so SECRETLESS_OS_KEYCHAIN=off
      // does not refuse it: this probe starts the planted `op` either way.
      expect(hanging.controlRun()).toBe(true);
      expect(hanging.pid()).toBeNull();
      const out = await runProbeInChild('isOnePasswordAvailable', process.platform, hanging.dir, 500);
      expect(out.signal, `probe did not return before the outer deadline\n${out.stderr}`).toBeNull();
      expect(out.status, out.stderr).toBe(0);
      const { result, elapsedMs } = JSON.parse(out.stdout);
      expect(result.available).toBe(false);
      expect(elapsedMs).toBeLessThan(5_000);
      const pid = hanging.pid();
      expect(pid).not.toBeNull();
      expect(processIsGone(pid!)).toBe(true);
    } finally {
      hanging.cleanup();
    }
  });
});
