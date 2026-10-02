import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { spawn } from 'child_process';
import { isKeychainAvailable } from './factory';
import { SECURITY_PROGRAM } from './keychain-macos';
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
      // Where /usr/bin/security does not exist (this lane, CI) the probe says
      // not accessible; where it does (a Mac) it says available. PATH had no
      // part in either answer.
      expect(result.available).toBe(fs.existsSync(SECURITY_PROGRAM));
    } finally {
      planted.cleanup();
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
process.stdout.write(JSON.stringify({ result, elapsedMs: Date.now() - start }));
`);
    return new Promise((resolve) => {
      const child = spawn(
        process.execPath,
        [harness, DIST_FACTORY, fn, platform, pathPrefix, String(childTimeoutMs)],
        { stdio: ['ignore', 'pipe', 'pipe'], timeout: OUTER_DEADLINE_MS, killSignal: 'SIGKILL' },
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
      const out = await runProbeInChild('isKeychainAvailable', 'linux', hanging.dir, 500);
      expect(out.signal, `probe did not return before the outer deadline\n${out.stderr}`).toBeNull();
      expect(out.status, out.stderr).toBe(0);
      const { result, elapsedMs } = JSON.parse(out.stdout);
      expect(result.available).toBe(false);
      expect(result.platform).toBe('Linux');
      expect(elapsedMs).toBeLessThan(5_000);
      const pid = hanging.pid();
      expect(pid).not.toBeNull();
      expect(processIsGone(pid!)).toBe(true);
    } finally {
      hanging.cleanup();
    }
  });

  it('SLS-10.AC4 isOnePasswordAvailable: an op that never exits returns "not available" within the bound and the child is gone', { timeout: OUTER_DEADLINE_MS + 5_000 }, async () => {
    const hanging = makeHangingProgram('op');
    try {
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
