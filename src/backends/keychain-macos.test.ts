import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import {
  MacOSKeychainBackend,
  KeychainLineError,
  SECURITY_PROGRAM,
  MAX_SECURITY_LINE_BYTES,
  buildAddGenericPasswordLine,
  decodeKeychainValue,
  keychainOutputIsHexEncoded,
  redactSecurityError,
} from './keychain-macos';
import { leaksAny } from '../redact';
import {
  makeSecurityRecorder,
  makeMarkerProgram,
  processIsGone,
  randomValue,
  waitForProcessGone,
  withPathPrefix,
  type Recorder,
  type RecordedCall,
} from './child-recorder.test-support';

/**
 * These tests run the backend's real child-process path against a recorder
 * program that stands in for `/usr/bin/security` (see
 * child-recorder.test-support.ts). They run on Linux, in the lane and in CI,
 * with no platform condition: nothing here needs a Keychain, and nothing here
 * ever touches one.
 */

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-keychain-macos-test-'));
}

function cleanup(dir: string): void {
  fs.rmSync(dir, { recursive: true, force: true });
}

const hex = (s: string) => Buffer.from(s, 'utf-8').toString('hex');

/** The `security -i` invocations among the recorded calls. */
const interactiveCalls = (calls: RecordedCall[]) => calls.filter(c => c.argv[0] === '-i');

describe('MacOSKeychainBackend against a security recorder', () => {
  let dir: string;
  let recorder: Recorder;
  let backend: MacOSKeychainBackend;

  beforeEach(() => {
    dir = tmpDir();
    recorder = makeSecurityRecorder();
    backend = new MacOSKeychainBackend({ storeDir: dir }, { securityProgram: recorder.program });
  });

  afterEach(() => {
    cleanup(dir);
    recorder.cleanup();
  });

  describe('C1: the value is on no child argument list and in no child environment', () => {
    it('SLS-10.AC1 store(V1) and store(V2) start children with identical argv and identical env, and both values reach stdin as hex', async () => {
      const v1 = randomValue(24);
      const v2 = randomValue(41);

      await backend.store('mcp/client/server/KEY', v1);
      const first = recorder.calls();
      await backend.store('mcp/client/server/KEY', v2);
      const second = recorder.calls().slice(first.length);

      // Reachability witness: the recorder ran for each store.
      expect(first.length).toBeGreaterThan(0);
      expect(second.length).toBeGreaterThan(0);
      expect(interactiveCalls(first)).toHaveLength(1);
      expect(interactiveCalls(second)).toHaveLength(1);

      // Differential cell: every child the store starts has the same argv and
      // the same environment whichever value was stored. Environments are
      // compared key by key and only the NAMES of differing keys are reported,
      // so a failure never prints the environment itself.
      expect(second.map(c => c.argv)).toEqual(first.map(c => c.argv));
      expect(second).toHaveLength(first.length);
      for (let i = 0; i < first.length; i++) {
        const keys = new Set([...Object.keys(first[i].env), ...Object.keys(second[i].env)]);
        const differing = [...keys].filter(k => first[i].env[k] !== second[i].env[k]);
        expect(differing, `env keys differing between store(V1) and store(V2), child ${i}`).toEqual([]);
      }

      // Positive control: the value did reach the child, on stdin, as hex.
      expect(interactiveCalls(first)[0].stdin).toContain(hex(v1));
      expect(interactiveCalls(second)[0].stdin).toContain(hex(v2));
    });

    it('SLS-10.AC1 no child argv and no child env carries the value or its hex', async () => {
      const value = randomValue(32);
      await backend.store('secret/API_KEY', value);

      const calls = recorder.calls();
      expect(calls.length).toBeGreaterThan(0);
      const carries = (s: string | undefined) => !!s && (s.includes(value) || s.includes(hex(value)));
      for (const call of calls) {
        const argvHits = call.argv.map((a, i) => (carries(a) ? `argv[${i}]` : null)).filter(Boolean);
        expect(argvHits).toEqual([]);
        // Only the names of offending variables are reported, never their values.
        const envHits = Object.entries(call.env).filter(([, v]) => carries(v)).map(([k]) => k);
        expect(envHits).toEqual([]);
      }
    });
  });

  describe('C2: program custody', () => {
    it('SLS-10.AC2 the program is /usr/bin/security by absolute path', () => {
      expect(SECURITY_PROGRAM).toBe('/usr/bin/security');
      expect(path.isAbsolute(SECURITY_PROGRAM)).toBe(true);
    });

    it('SLS-10.AC2 a security planted first on PATH never runs: not with the recorder seam, not with the default program', async () => {
      const planted = makeMarkerProgram('security');
      try {
        // Positive control: the planted program does run when started, so
        // "never ran" below is a finding and not a broken fixture.
        expect(planted.controlRun()).toBe(true);
        expect(planted.ran()).toBe(false);

        await withPathPrefix(planted.dir, async () => {
          // With the seam: every call goes to the recorder.
          await backend.store('secret/K', 'value-one');
          await backend.resolve('secret/K');
          await backend.delete('secret/K');
          await backend.healthCheck();
          expect(planted.ran()).toBe(false);

          // Without the seam: the program is /usr/bin/security, by absolute
          // path. The suite runs with SECRETLESS_OS_KEYCHAIN=off
          // (vitest.config.ts), so that exact program is refused before it
          // starts, and the refusal names the variable. PATH decided nothing.
          const plain = new MacOSKeychainBackend({ storeDir: dir });
          await expect(plain.healthCheck()).rejects.toThrow(/SECRETLESS_OS_KEYCHAIN/);
          expect(planted.ran()).toBe(false);
        });
      } finally {
        planted.cleanup();
      }
    });

    it('SLS-10.AC2 the recorder seam is a constructor parameter only: a config key or environment variable of the same name is ignored', async () => {
      const keys = ['securityProgram', 'security', 'securityPath', 'program'];
      const configured = new MacOSKeychainBackend(
        { storeDir: dir, ...Object.fromEntries(keys.map(k => [k, recorder.program])) },
      );
      const saved = { ...process.env };
      try {
        for (const name of ['SECRETLESS_SECURITY_PROGRAM', 'SECURITY_PROGRAM', 'SECURITY', 'SECRETLESS_SECURITY']) {
          process.env[name] = recorder.program;
        }
        // Refused under SECRETLESS_OS_KEYCHAIN=off, which only refuses the
        // exact program /usr/bin/security: the recorder was not the program.
        await expect(configured.healthCheck()).rejects.toThrow(/SECRETLESS_OS_KEYCHAIN/);
        expect(recorder.calls()).toEqual([]);
      } finally {
        for (const name of Object.keys(process.env)) {
          if (!(name in saved)) delete process.env[name];
        }
        Object.assign(process.env, saved);
      }
    });

    it('SLS-10.AC2 keychain-macos.ts, factory.ts and bounded-child.ts read nothing from the environment that could name a program or a bound', () => {
      const read = (file: string) => fs.readFileSync(path.join(__dirname, file), 'utf-8');
      const envReads = (source: string) => [...source.matchAll(/process\.env\.(\w+)/g)].map(m => m[1]);

      const macos = read('keychain-macos.ts');
      expect(new Set(envReads(macos))).toEqual(new Set(['HOME', 'USERPROFILE']));
      expect(macos).not.toMatch(/process\.env\[/);
      expect(macos).not.toMatch(/process\.argv/);

      const factory = read('factory.ts');
      expect(new Set(envReads(factory))).toEqual(new Set(['PATH', 'PATHEXT', 'VAULT_ADDR', 'VAULT_TOKEN']));
      expect(factory).not.toMatch(/process\.env\[/);
      expect(factory).not.toMatch(/process\.argv/);
      // Every `security` the factory names is the absolute one.
      expect(factory).not.toMatch(/['"]security['"]/);

      // The one variable the chokepoint reads can only refuse a program.
      const boundedChild = read('bounded-child.ts');
      expect(new Set(envReads(boundedChild))).toEqual(new Set(['SECRETLESS_OS_KEYCHAIN']));
      expect(boundedChild).not.toMatch(/process\.env\[/);
      expect(boundedChild).not.toMatch(/process\.argv/);
    });
  });

  describe('C3: no operand is parsed as command text', () => {
    it('SLS-10.AC3 one store writes exactly one line, the value travels as -X hex, and every other operand is double-quoted with M1 quoting', async () => {
      const key = 'secret/na"me\\with:odd chars';
      const value = 'value with spaces "quotes" and \\ backslashes: ok';
      await backend.store(key, value);

      const lines = interactiveCalls(recorder.calls()).map(c => c.stdin.split('\n').filter(l => l.length > 0));
      expect(lines).toHaveLength(1);
      expect(lines[0]).toHaveLength(1);
      const line = lines[0][0];

      const q = (s: string) => `"${s.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
      expect(line).toBe(
        `add-generic-password -s ${q('Secretless: na"me\\with:odd chars')} -a ${q(key)} -l ${q(`Secretless: ${key}`)} -U -X ${hex(value)}`,
      );
      expect(line).not.toContain('-w');
      expect(line).not.toContain(value);
      expect(Buffer.byteLength(line + '\n', 'utf-8')).toBeLessThanOrEqual(MAX_SECURITY_LINE_BYTES);

      // And the recorder, parsing the line the way M1 measured, stored the
      // intended operands: the round trip returns the value under the key.
      expect(await backend.resolve(key)).toEqual({ [key]: value });
    });

    it('SLS-10.AC3 a value holding a newline and a second command reaches the recorder as one line, and that command never runs', async () => {
      const value = 'first-line\nadd-generic-password -s "x" -a "planted-by-value" -U -X 41\n';
      await backend.store('secret/MULTI', value);

      const calls = interactiveCalls(recorder.calls());
      expect(calls).toHaveLength(1);
      const nonEmpty = calls[0].stdin.split('\n').filter(l => l.length > 0);
      expect(nonEmpty).toHaveLength(1);
      expect(nonEmpty[0]).toContain(`-X ${hex(value)}`);
      expect(calls[0].stdin).not.toContain('planted-by-value');

      // Only the intended item exists; the read path decoded the hex form
      // the CLI returns for a value with a non-printable byte.
      const state = JSON.parse(fs.readFileSync(path.join(recorder.dir, 'state.json'), 'utf-8'));
      expect(Object.keys(state)).toHaveLength(1);
      expect(await backend.resolve('secret/MULTI')).toEqual({ 'secret/MULTI': value });
    });

    it('SLS-10.AC3 a key holding a newline and a second command is refused by name and no child starts', async () => {
      const key = 'secret/K\nadd-generic-password -s "x" -a "planted-by-key" -U -X 41';
      const err = await backend.store(key, 'value').catch((e: Error) => e);
      expect(err).toBeInstanceOf(KeychainLineError);
      expect((err as KeychainLineError).name).toBe('KeychainLineError');
      expect((err as KeychainLineError).reason).toBe('operand-newline');
      expect((err as Error).message).toMatch(/Verify:/);
      expect((err as Error).message).toMatch(/Fix:/);
      expect(recorder.calls()).toEqual([]);
    });

    it('SLS-10.AC3 a value that does not fit on one line is refused by name and no child starts', async () => {
      // leaksAny reports any 4-character run the message shares with the value
      // or its hex, so a value drawn from the full alphabet shares one with the
      // fixed refusal text now and then, and the test failed at random. The
      // text depends only on the value's length: read it once with a filler,
      // then draw the value only from printable characters that text does not
      // contain and whose hex form ends in a-f. No run of the value can then
      // occur in the text, and a run of its hex would need the shape guarded
      // below.
      const filler = await backend.store('secret/BIG', '.'.repeat(2100)).catch((e: Error) => e);
      expect(filler).toBeInstanceOf(KeychainLineError);
      const fixedText = (filler as Error).message;
      const alphabet = Array.from({ length: 0x7e - 0x21 + 1 }, (_, i) => String.fromCharCode(0x21 + i))
        .filter((c) => c.charCodeAt(0) % 16 >= 10 && !fixedText.includes(c));
      expect(alphabet.length, `characters left for the value: ${alphabet.join('')}`).toBeGreaterThanOrEqual(8);
      expect(fixedText).not.toMatch(/[2-7][a-f][2-7][a-f]|[a-f][2-7][a-f][2-7]/);
      let value = '';
      for (let i = 0; i < 2100; i++) value += alphabet[Math.floor(Math.random() * alphabet.length)];

      const err = await backend.store('secret/BIG', value).catch((e: Error) => e);
      expect((err as Error).message, 'the refusal text depends on the length alone').toBe(fixedText);
      expect(err).toBeInstanceOf(KeychainLineError);
      expect((err as KeychainLineError).reason).toBe('line-too-long');
      expect((err as Error).message).not.toContain(value);
      expect(leaksAny((err as Error).message, [value, hex(value)])).toBe(false);
      expect(recorder.calls()).toEqual([]);
    });

    it('SLS-10.AC3 buildAddGenericPasswordLine refuses a line break in any operand and an empty value', () => {
      expect(() => buildAddGenericPasswordLine('Secretless: K\n', 'k', 'l', 'v')).toThrow(KeychainLineError);
      expect(() => buildAddGenericPasswordLine('s', 'k\r', 'l', 'v')).toThrow(KeychainLineError);
      expect(() => buildAddGenericPasswordLine('s', 'k', 'l\nquit', 'v')).toThrow(KeychainLineError);
      expect(() => buildAddGenericPasswordLine('s', 'k', 'l', '')).toThrow(/empty/);
      expect(buildAddGenericPasswordLine('s', 'k', 'l', 'v')).toBe('add-generic-password -s "s" -a "k" -l "l" -U -X 76\n');
    });
  });

  describe('C4: every child call is bounded', () => {
    // The hanging child's pid is the one it wrote. Each cell first runs the
    // recorder outside the bound (positive control, and the slow first start
    // paid there), so the bounded child can write its pid inside 0.5s.
    async function expectHungChildGone(): Promise<void> {
      const pid = recorder.takeHangPid();
      expect(pid, 'the hanging security wrote no pid before the bound ended it').not.toBeNull();
      expect(await waitForProcessGone(pid!), `pid ${pid} is still running`).toBe(true);
    }

    it('SLS-10.AC4 a security that never exits: store throws within the bound and the child is gone', { timeout: 10_000 }, async () => {
      expect(recorder.controlRun()).toBe(true);
      recorder.setMode({ kind: 'hang' });
      const bounded = new MacOSKeychainBackend({ storeDir: dir }, { securityProgram: recorder.program, childTimeoutMs: 500 });

      const start = Date.now();
      await expect(bounded.store('secret/K', 'value')).rejects.toThrow(/did not respond within 0\.5s/);
      expect(Date.now() - start).toBeLessThan(5_000);
      await expectHungChildGone();
    });

    it('SLS-10.AC4 a security that never exits: resolve throws within the bound and the child is gone', { timeout: 10_000 }, async () => {
      fs.writeFileSync(path.join(dir, 'keychain-index.json'), JSON.stringify(['secret/K']));
      expect(recorder.controlRun()).toBe(true);
      recorder.setMode({ kind: 'hang' });
      const bounded = new MacOSKeychainBackend({ storeDir: dir }, { securityProgram: recorder.program, childTimeoutMs: 500 });

      const start = Date.now();
      await expect(bounded.resolve('secret/K')).rejects.toThrow(/did not respond within 0\.5s/);
      expect(Date.now() - start).toBeLessThan(5_000);
      await expectHungChildGone();
    });

    it('SLS-10.AC4 a security that never exits: delete and healthCheck return within the bound and the child is gone', { timeout: 10_000 }, async () => {
      expect(recorder.controlRun()).toBe(true);
      recorder.setMode({ kind: 'hang' });
      const bounded = new MacOSKeychainBackend({ storeDir: dir }, { securityProgram: recorder.program, childTimeoutMs: 500 });

      let start = Date.now();
      expect(await bounded.delete('secret/K')).toBe(false);
      expect(Date.now() - start).toBeLessThan(5_000);
      await expectHungChildGone();

      start = Date.now();
      const health = await bounded.healthCheck();
      expect(Date.now() - start).toBeLessThan(5_000);
      expect(health.healthy).toBe(false);
      expect(health.message).toMatch(/did not respond within 0\.5s/);
      await expectHungChildGone();
    });

    it('a pid already checked is not read again for the next bounded call', async () => {
      // delete and healthCheck run one after the other: a healthCheck child
      // ended before it wrote its pid must read as no pid, not as the pid the
      // delete child wrote, which is gone and would pass the check.
      const exited = spawnSync(process.execPath, ['-e', '']).pid;
      fs.writeFileSync(path.join(recorder.dir, 'hang.pid'), String(exited));
      await expectHungChildGone();
      expect(recorder.takeHangPid()).toBeNull();
    });

    it('a pid that was never written is refused, never read as a child still running', () => {
      // A hanging child ended before it writes its pid leaves takeHangPid() null,
      // or 0 for an empty file. process.kill refuses null and signals this
      // process group for 0, so either used to read as "still running".
      expect(recorder.takeHangPid()).toBeNull();
      expect(() => processIsGone(recorder.takeHangPid()!)).toThrow(/not a recorded pid/);
      expect(() => processIsGone(0)).toThrow(/not a recorded pid/);
      expect(processIsGone(process.pid)).toBe(false);
    });
  });

  describe('C5: no value in any error', () => {
    // Fixed, not random: a random value could share a four-character run with
    // the message text by chance, and the redactor would then drop the detail
    // the marker assertion needs. No run of this one occurs in any message.
    const VALUE = 'Zq9vXw7Tk41Qp';
    const MARKER = 'planted-stderr-marker';

    function assertClean(err: Error): void {
      expect(err.message).not.toContain(VALUE);
      expect(err.message).not.toContain(hex(VALUE));
      expect(leaksAny(err.message, [VALUE, hex(VALUE)])).toBe(false);
      expect(leaksAny(err.stack ?? '', [VALUE, hex(VALUE)])).toBe(false);
      const carried = err as Error & { stdout?: unknown; stderr?: unknown };
      expect(leaksAny(String(carried.stdout ?? ''), [VALUE, hex(VALUE)])).toBe(false);
      expect(leaksAny(String(carried.stderr ?? ''), [VALUE, hex(VALUE)])).toBe(false);
      expect(err.message).toMatch(/Verify:\s+\S/);
      expect(err.message).toMatch(/Fix:\s+\S/);
    }

    it('SLS-10.AC5 a non-zero exit: the error carries neither the value nor its hex, keeps the planted stderr marker, and says what happened', async () => {
      recorder.setMode({
        kind: 'fail',
        status: 1,
        stderr: `security: SecKeychainItemCreateFromContent (<default>): ${MARKER}: The authorization was canceled by the user.\n`,
      });
      const err = await backend.store('secret/K', VALUE).catch((e: Error) => e) as Error;
      expect(err).toBeInstanceOf(Error);
      expect(err.message).toMatch(/Could not store "secret\/K"/);
      expect(err.message).toContain(MARKER);
      expect(err.message).toMatch(/exit status 1/);
      expect(err.message).toMatch(/declined the write/);
      assertClean(err);
    });

    it('SLS-10.AC5 a non-zero exit that echoes the value and its hex on stderr: neither reaches the error', async () => {
      recorder.setMode({
        kind: 'fail',
        status: 1,
        stderr: `security: rejected ${VALUE} and ${hex(VALUE)}\n`,
        stdout: `security> echo ${hex(VALUE)}\n`,
      });
      const err = await backend.store('secret/K', VALUE).catch((e: Error) => e) as Error;
      expect(err.message).toMatch(/Could not store "secret\/K"/);
      assertClean(err);
    });

    it('SLS-10.AC5 a timeout: the error carries neither the value nor its hex and says what happened', { timeout: 10_000 }, async () => {
      recorder.setMode({ kind: 'hang' });
      const bounded = new MacOSKeychainBackend({ storeDir: dir }, { securityProgram: recorder.program, childTimeoutMs: 300 });
      const err = await bounded.store('secret/K', VALUE).catch((e: Error) => e) as Error;
      expect(err.message).toMatch(/Could not store "secret\/K"/);
      expect(err.message).toMatch(/did not respond within 0\.3s/);
      expect(err.message).toMatch(/did not answer in time/);
      assertClean(err);
    });
  });

  describe('C6: a store that did not commit is a thrown failure', () => {
    it('SLS-10.AC6 a write that exits 0 without landing is a thrown failure and the key is not indexed', async () => {
      recorder.setMode({ kind: 'drop' });
      const err = await backend.store('secret/K', 'value-one').catch((e: Error) => e) as Error;
      expect(err.message).toMatch(/Could not confirm "secret\/K" was stored/);
      expect(err.message).toMatch(/no entry could be read back/);
      expect(err.message).not.toContain('value-one');
      expect(err.message).toMatch(/Verify:/);
      expect(err.message).toMatch(/Fix:/);
      expect(fs.existsSync(path.join(dir, 'keychain-index.json'))).toBe(false);
    });

    it('SLS-10.AC6 a write that exits 0 but landed a different value is a thrown failure', async () => {
      recorder.setMode({ kind: 'wrong' });
      const err = await backend.store('secret/K', 'value-one').catch((e: Error) => e) as Error;
      expect(err.message).toMatch(/Could not confirm "secret\/K" was stored/);
      expect(err.message).toMatch(/different/);
      expect(err.message).not.toContain('value-one');
      expect(err.message).not.toContain('a-different-value');
    });

    it('SLS-10.AC6 every store is followed by a read-back of the same entry', async () => {
      await backend.store('mcp/client/server/KEY', 'v');
      const argvs = recorder.calls().map(c => c.argv);
      const add = argvs.findIndex(a => a[0] === '-i');
      const readBack = argvs.findIndex(a => a[0] === 'find-generic-password' && a.includes('-w'));
      expect(add).toBeGreaterThanOrEqual(0);
      expect(readBack).toBeGreaterThan(add);
      expect(argvs[readBack]).toEqual(['find-generic-password', '-s', 'Secretless: KEY', '-a', 'mcp/client/server/KEY', '-w']);
    });
  });

  describe('store()', () => {
    it('writes with an in-place update and sweeps the legacy entry after', async () => {
      await backend.store('mcp/client/server/KEY', 'secret-value');

      const argvs = recorder.calls().map(c => c.argv);
      const add = argvs.findIndex(a => a[0] === '-i');
      const legacySweep = argvs.findIndex(a =>
        a[0] === 'delete-generic-password' && a.includes('secretless'));

      // `-U` updates in place, so no delete of the live entry precedes the
      // write. The previous ordering deleted first and lost the credential
      // outright whenever the add then failed.
      expect(add).toBeGreaterThanOrEqual(0);
      expect(argvs.slice(0, add).some(a => a[0] === 'delete-generic-password')).toBe(false);
      expect(interactiveCalls(recorder.calls())[0].stdin).toMatch(/^add-generic-password .* -U -X [0-9a-f]+\n$/);

      // The live entry is never deleted as part of a write.
      expect(argvs).not.toContainEqual(
        ['delete-generic-password', '-s', 'Secretless: KEY', '-a', 'mcp/client/server/KEY'],
      );

      // The legacy duplicate is still swept, after the value is committed.
      expect(legacySweep).toBeGreaterThan(add);
      expect(argvs[legacySweep]).toEqual(
        ['delete-generic-password', '-s', 'secretless', '-a', 'mcp/client/server/KEY'],
      );
    });

    it('updates the key index file', async () => {
      await backend.store('mcp/client/server/KEY', 'val');

      const indexPath = path.join(dir, 'keychain-index.json');
      const index = JSON.parse(fs.readFileSync(indexPath, 'utf-8'));
      expect(index).toContain('mcp/client/server/KEY');
    });

    it('does not duplicate keys in index', async () => {
      await backend.store('mcp/client/server/KEY', 'val1');
      await backend.store('mcp/client/server/KEY', 'val2');

      const indexPath = path.join(dir, 'keychain-index.json');
      const index = JSON.parse(fs.readFileSync(indexPath, 'utf-8'));
      const count = index.filter((k: string) => k === 'mcp/client/server/KEY').length;
      expect(count).toBe(1);
    });

    it('is wired to redactSecurityError: a failure message holds the key and not the value', async () => {
      recorder.setMode({
        kind: 'fail',
        status: 1,
        stderr: 'security: The authorization was canceled by the user.\n',
      });
      await expect(backend.store('secret/NUTEST', 'hello-world-123')).rejects.toThrow(
        /Could not store "secret\/NUTEST"/,
      );
    });
  });

  describe('resolve()', () => {
    it('resolves matching keys from index', async () => {
      await backend.store('mcp/client/server/KEY1', 'value1');
      await backend.store('mcp/client/server/KEY2', 'value2');
      await backend.store('mcp/other/server/KEY3', 'value3');

      const result = await backend.resolve('mcp/client/server');
      expect(result).toEqual({
        'mcp/client/server/KEY1': 'value1',
        'mcp/client/server/KEY2': 'value2',
      });
    });

    it('returns empty object when no matching keys', async () => {
      const indexPath = path.join(dir, 'keychain-index.json');
      fs.writeFileSync(indexPath, JSON.stringify(['mcp/other/server/KEY']));

      const result = await backend.resolve('mcp/client/server');
      expect(result).toEqual({});
      expect(recorder.calls()).toEqual([]);
    });

    it('skips keys the Keychain says are absent', async () => {
      // 44 is what `security` exits with for "The specified item could not be
      // found in the keychain". The recorder answers 44 for an item it never
      // stored. This one really is absent.
      const indexPath = path.join(dir, 'keychain-index.json');
      fs.writeFileSync(indexPath, JSON.stringify(['mcp/client/server/KEY1']));

      const result = await backend.resolve('mcp/client/server');
      expect(result).toEqual({});
      // Both the per-key and the legacy service were asked.
      expect(recorder.calls().map(c => c.argv[2])).toEqual(['Secretless: KEY1', 'secretless']);
    });

    it('refuses to report a key absent when the Keychain would not answer', async () => {
      // A locked Keychain, or a dismissed approval dialog, used to make every
      // secret read as missing with exit 0 (#104).
      const indexPath = path.join(dir, 'keychain-index.json');
      fs.writeFileSync(indexPath, JSON.stringify(['mcp/client/server/KEY1']));
      recorder.setMode({ kind: 'fail', status: 51, stderr: 'security: User interaction is not allowed.\n' });

      await expect(backend.resolve('mcp/client/server')).rejects.toThrow(
        /would not return "mcp\/client\/server\/KEY1"/,
      );
    });

    it('keeps a value with trailing whitespace intact', async () => {
      await backend.store('secret/TRAIL', 'ends-with-space ');
      expect(await backend.resolve('secret/TRAIL')).toEqual({ 'secret/TRAIL': 'ends-with-space ' });
    });
  });

  describe('delete()', () => {
    it('deletes both new and legacy entries and removes from index', async () => {
      await backend.store('mcp/client/server/KEY1', 'v1');
      await backend.store('mcp/client/server/KEY2', 'v2');

      const result = await backend.delete('mcp/client/server/KEY1');
      expect(result).toBe(true);

      const argvs = recorder.calls().map(c => c.argv);
      expect(argvs).toContainEqual(
        ['delete-generic-password', '-s', 'Secretless: KEY1', '-a', 'mcp/client/server/KEY1'],
      );
      expect(argvs).toContainEqual(
        ['delete-generic-password', '-s', 'secretless', '-a', 'mcp/client/server/KEY1'],
      );

      const indexPath = path.join(dir, 'keychain-index.json');
      const updatedIndex = JSON.parse(fs.readFileSync(indexPath, 'utf-8'));
      expect(updatedIndex).not.toContain('mcp/client/server/KEY1');
      expect(updatedIndex).toContain('mcp/client/server/KEY2');
      expect(await backend.resolve('mcp/client/server')).toEqual({ 'mcp/client/server/KEY2': 'v2' });
    });

    it('returns false when nothing was there to delete', async () => {
      const result = await backend.delete('nonexistent');
      expect(result).toBe(false);
    });
  });

  describe('healthCheck()', () => {
    it('returns healthy when security answers', async () => {
      const health = await backend.healthCheck();
      expect(health.healthy).toBe(true);
      expect(health.message).toContain('macOS Keychain available');
      expect(recorder.calls().map(c => c.argv)).toEqual([['default-keychain']]);
    });

    it('returns unhealthy when security fails', async () => {
      recorder.setMode({ kind: 'fail', status: 1, stderr: 'no keychain\n' });
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
    let probed = 0;
    const probe = () => { probed++; return true; };
    for (const v of ['not-hex-at-all', 'abc', '', 'zzzz']) {
      expect(decodeKeychainValue(v, probe)).toBe(v);
    }
    expect(probed).toBe(0);
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
  let dir: string;
  let recorder: Recorder;

  beforeEach(() => {
    dir = tmpDir();
    recorder = makeSecurityRecorder();
  });

  afterEach(() => {
    cleanup(dir);
    recorder.cleanup();
  });

  it('does not corrupt a stored 32-hex token', async () => {
    const backend = new MacOSKeychainBackend({ storeDir: dir }, { securityProgram: recorder.program });
    await backend.store('secret/TOKEN', HEX32_TOKEN);
    // The recorder, like macOS, reports a printable value as plain text
    // (quoted, no 0x) on `-g`, so it must not be decoded.
    const out = await backend.resolve('secret/TOKEN');
    expect(out['secret/TOKEN']).toBe(HEX32_TOKEN);
    const probes = recorder.calls().filter(c => c.argv[0] === 'find-generic-password' && c.argv.includes('-g'));
    expect(probes.length).toBeGreaterThan(0);
  });

  it('decodes a stored value macOS actually hex-encoded', async () => {
    const backend = new MacOSKeychainBackend({ storeDir: dir }, { securityProgram: recorder.program });
    await backend.store('secret/MULTILINE', 'line1\nline2');
    const out = await backend.resolve('secret/MULTILINE');
    expect(out['secret/MULTILINE']).toBe('line1\nline2');
  });

  it('refuses rather than guess when the -g probe does not complete', async () => {
    const backend = new MacOSKeychainBackend({ storeDir: dir }, { securityProgram: recorder.program });
    await backend.store('secret/TOKEN', HEX32_TOKEN);
    // `-w` still answers; only the `-g` probe fails. The value is shaped like
    // hex and the question that settles it went unanswered: refuse.
    recorder.setMode({ kind: 'probe-fails' });
    await expect(backend.resolve('secret/TOKEN')).rejects.toThrow(/Could not determine how the macOS Keychain stored "secret\/TOKEN"/);
  });
});

/**
 * The value is never on the child's argv now, but `security` can still echo
 * what it was given, and an error constructed elsewhere can still arrive with
 * the value in it. The redaction is the last line, and it is tested as such.
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

  it('scrubs the hex form of the value as well as the value', () => {
    const err = redactSecurityError(
      new Error(`security: rejected -X ${hex(SECRET)}\nsecurity: the thing broke`),
      SECRET,
      'secret/K',
    );
    expect(err.message).not.toContain(hex(SECRET));
    expect(leaksAny(err.message, [SECRET, hex(SECRET)])).toBe(false);
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

  it('routes a timeout to advice about the waiting dialog', () => {
    const err = redactSecurityError(
      new Error('security did not respond within 30s'),
      SECRET,
      'secret/K',
    );
    expect(err.message).toMatch(/did not answer in time/);
    expect(err.message).toMatch(/Verify:\s+security default-keychain/);
    expect(err.message).toMatch(/Fix:/);
  });

  it('discards the detail rather than leaking when scrubbing cannot clear it', () => {
    // A value that survives naive scrubbing because it reappears after
    // replacement: splitting on "aa" in "aaa" leaves an "a" behind.
    const tricky = 'aa';
    const err = redactSecurityError(new Error('security: aaaaa failed'), tricky, 'secret/K');
    expect(err.message).not.toContain(tricky);
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
