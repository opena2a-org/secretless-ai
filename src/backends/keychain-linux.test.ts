import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { LinuxKeychainBackend } from './keychain-linux';
import {
  makeSecretToolRecorder,
  waitForProcessGone,
  type Recorder,
} from './child-recorder.test-support';

/**
 * These tests run the backend's real child-process path against a recorder
 * program that stands in for `secret-tool` (see child-recorder.test-support.ts).
 * No Secret Service is needed, and none is touched.
 */

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-keychain-linux-test-'));
}

function cleanup(dir: string): void {
  fs.rmSync(dir, { recursive: true, force: true });
}

describe('LinuxKeychainBackend', () => {
  let dir: string;
  let recorder: Recorder;
  let backend: LinuxKeychainBackend;

  beforeEach(() => {
    dir = tmpDir();
    recorder = makeSecretToolRecorder();
    backend = new LinuxKeychainBackend({ storeDir: dir }, { secretToolProgram: recorder.program });
  });

  afterEach(() => {
    cleanup(dir);
    recorder.cleanup();
  });

  describe('store()', () => {
    it('calls secret-tool store with per-key service name and the value on stdin only', async () => {
      await backend.store('mcp/client/server/KEY', 'secret-value');

      const calls = recorder.calls();
      // Legacy clear first, then the store.
      expect(calls.map(c => c.argv)).toEqual([
        ['clear', 'service', 'secretless', 'account', 'mcp/client/server/KEY'],
        ['store', '--label=Secretless: mcp/client/server/KEY', 'service', 'Secretless: KEY', 'account', 'mcp/client/server/KEY'],
      ]);
      expect(calls[1].stdin).toBe('secret-value');
      for (const call of calls) {
        expect(JSON.stringify(call.argv)).not.toContain('secret-value');
        expect(JSON.stringify(call.env)).not.toContain('secret-value');
      }
    });

    it('updates the key index file', async () => {
      await backend.store('mcp/client/server/KEY', 'val');

      const indexPath = path.join(dir, 'keychain-index.json');
      const index = JSON.parse(fs.readFileSync(indexPath, 'utf-8'));
      expect(index).toContain('mcp/client/server/KEY');
    });

    it('throws when secret-tool store fails, naming the key and not the value', async () => {
      recorder.setMode({ kind: 'fail', status: 1, stderr: 'secret-tool: Cannot create an item in a locked collection\n' });
      const err = await backend.store('secret/K', 'Zq9vXw7Tk41Qp').catch((e: Error) => e) as Error;
      expect(err.message).toMatch(/Could not store "secret\/K"/);
      expect(err.message).toContain('locked collection');
      expect(err.message).not.toContain('Zq9vXw7Tk41Qp');
      expect(err.message).toMatch(/Verify:/);
      expect(err.message).toMatch(/Fix:/);
      expect(fs.existsSync(path.join(dir, 'keychain-index.json'))).toBe(false);
    });
  });

  describe('C4: every child call is bounded', () => {
    // The hanging child's pid is the one it wrote. Each cell first runs the
    // recorder outside the bound (positive control, and the slow first start
    // paid there), so the bounded child can write its pid inside 0.5s.
    async function expectHungChildGone(): Promise<void> {
      const pid = recorder.hangPid();
      expect(pid, 'the hanging secret-tool wrote no pid before the bound ended it').not.toBeNull();
      expect(await waitForProcessGone(pid!), `pid ${pid} is still running`).toBe(true);
    }

    it('SLS-10.AC4 a secret-tool that never exits: store throws within the bound and the child is gone', { timeout: 10_000 }, async () => {
      expect(recorder.controlRun()).toBe(true);
      recorder.setMode({ kind: 'hang' });
      const bounded = new LinuxKeychainBackend({ storeDir: dir }, { secretToolProgram: recorder.program, childTimeoutMs: 500 });

      const start = Date.now();
      await expect(bounded.store('secret/K', 'value')).rejects.toThrow(/did not respond within 0\.5s/);
      expect(Date.now() - start).toBeLessThan(5_000);
      await expectHungChildGone();
    });

    it('SLS-10.AC4 a secret-tool that never exits: resolve throws within the bound and the child is gone', { timeout: 10_000 }, async () => {
      fs.writeFileSync(path.join(dir, 'keychain-index.json'), JSON.stringify(['secret/K']));
      expect(recorder.controlRun()).toBe(true);
      recorder.setMode({ kind: 'hang' });
      const bounded = new LinuxKeychainBackend({ storeDir: dir }, { secretToolProgram: recorder.program, childTimeoutMs: 500 });

      const start = Date.now();
      await expect(bounded.resolve('secret/K')).rejects.toThrow(/did not respond within 0\.5s/);
      expect(Date.now() - start).toBeLessThan(5_000);
      await expectHungChildGone();
    });

    it('SLS-10.AC4 a secret-tool that never exits: delete returns within the bound and the child is gone', { timeout: 10_000 }, async () => {
      expect(recorder.controlRun()).toBe(true);
      recorder.setMode({ kind: 'hang' });
      const bounded = new LinuxKeychainBackend({ storeDir: dir }, { secretToolProgram: recorder.program, childTimeoutMs: 500 });

      const start = Date.now();
      expect(await bounded.delete('secret/K')).toBe(false);
      expect(Date.now() - start).toBeLessThan(5_000);
      await expectHungChildGone();
    });
  });

  describe('resolve()', () => {
    it('resolves matching keys from index', async () => {
      await backend.store('mcp/client/server/KEY1', 'value1');
      await backend.store('mcp/client/server/KEY2', 'value2');
      await backend.store('mcp/other/KEY3', 'value3');

      const result = await backend.resolve('mcp/client/server');
      expect(result).toEqual({
        'mcp/client/server/KEY1': 'value1',
        'mcp/client/server/KEY2': 'value2',
      });
    });

    it('falls back to the legacy service name', async () => {
      fs.writeFileSync(path.join(dir, 'keychain-index.json'), JSON.stringify(['mcp/client/server/KEY1']));
      // Seed a legacy-named item directly in the recorder's state.
      fs.writeFileSync(
        path.join(recorder.dir, 'state.json'),
        JSON.stringify({ 'secretless\u0000mcp/client/server/KEY1': 'legacy-value' }),
      );
      expect(await backend.resolve('mcp/client/server')).toEqual({ 'mcp/client/server/KEY1': 'legacy-value' });
    });

    it('skips keys the Secret Service says are absent', async () => {
      // An absent entry: `lookup` exits 1 saying nothing, and `search` with
      // the same attributes exits 0 listing nothing. This one really is absent.
      fs.writeFileSync(path.join(dir, 'keychain-index.json'), JSON.stringify(['mcp/client/server/KEY1']));

      expect(await backend.resolve('mcp/client/server')).toEqual({});
      // Both the per-key and the legacy service were asked, and each silent
      // lookup was settled by a search for the same attributes.
      expect(recorder.calls().map(c => c.argv.slice(0, 3))).toEqual([
        ['lookup', 'service', 'Secretless: KEY1'],
        ['search', 'service', 'Secretless: KEY1'],
        ['lookup', 'service', 'secretless'],
        ['search', 'service', 'secretless'],
      ]);
    });

    it('does not search when lookup returns the value', async () => {
      await backend.store('mcp/client/server/KEY1', 'value1');
      const before = recorder.calls().length;

      expect(await backend.resolve('mcp/client/server')).toEqual({ 'mcp/client/server/KEY1': 'value1' });
      expect(recorder.calls().slice(before).map(c => c.argv[0])).toEqual(['lookup']);
    });

    it('refuses to report a key absent when its collection is locked', async () => {
      // In a locked collection whose unlock dialog is not answered, `lookup`
      // exits 1 saying nothing, exactly as it does for an absent entry. That
      // used to make every secret read as missing with exit 0 (#130).
      await backend.store('mcp/client/server/KEY1', 'locked-secret-value');
      recorder.setMode({ kind: 'locked' });

      const err = await backend.resolve('mcp/client/server').then(
        () => { throw new Error('resolve did not reject'); },
        (e: Error) => e,
      );
      expect(err.message).toMatch(/would not return "mcp\/client\/server\/KEY1"/);
      expect(err.message).toMatch(/holds an entry with these attributes and did not return its value/);
      expect(err.message).toContain('org.freedesktop.Secret.Collection Locked');
      expect(err.message).not.toContain('locked-secret-value');
    });

    it('refuses to report a key absent when the legacy entry sits in a locked collection', async () => {
      fs.writeFileSync(path.join(dir, 'keychain-index.json'), JSON.stringify(['mcp/client/server/KEY1']));
      fs.writeFileSync(
        path.join(recorder.dir, 'state.json'),
        JSON.stringify({ 'secretless\u0000mcp/client/server/KEY1': 'legacy-value' }),
      );
      recorder.setMode({ kind: 'locked' });

      await expect(backend.resolve('mcp/client/server')).rejects.toThrow(
        /would not return "mcp\/client\/server\/KEY1"/,
      );
    });

    it('refuses to report a key absent when no Secret Service is reachable', async () => {
      // Measured: with no session bus, `lookup` exits 1 and says why on stderr.
      fs.writeFileSync(path.join(dir, 'keychain-index.json'), JSON.stringify(['mcp/client/server/KEY1']));
      recorder.setMode({ kind: 'fail', status: 1, stderr: 'secret-tool: Cannot autolaunch D-Bus without X11 $DISPLAY\n' });

      const err = await backend.resolve('mcp/client/server').then(
        () => { throw new Error('resolve did not reject'); },
        (e: Error) => e,
      );
      expect(err.message).toMatch(/would not return "mcp\/client\/server\/KEY1"/);
      expect(err.message).toContain('secret-tool lookup exit status: 1');
      expect(err.message).toContain('Cannot autolaunch D-Bus without X11 $DISPLAY');
      // The lookup's answer was an error, so no search was needed to settle it.
      expect(recorder.calls().map(c => c.argv[0])).toEqual(['lookup']);
    });

    it('refuses to report a key absent when the search that would settle it also fails', async () => {
      // A silent exit 1 from `search` is not what an absent entry looks like:
      // that is exit 0 with nothing listed.
      fs.writeFileSync(path.join(dir, 'keychain-index.json'), JSON.stringify(['mcp/client/server/KEY1']));
      recorder.setMode({ kind: 'fail', status: 1, stderr: '' });

      await expect(backend.resolve('mcp/client/server')).rejects.toThrow(
        /would not return "mcp\/client\/server\/KEY1"[\s\S]*secret-tool search exit status: 1/,
      );
    });
  });

  describe('delete()', () => {
    it('deletes both new and legacy entries and removes from index', async () => {
      await backend.store('mcp/client/server/KEY1', 'v1');

      const result = await backend.delete('mcp/client/server/KEY1');
      expect(result).toBe(true);

      const argvs = recorder.calls().map(c => c.argv);
      expect(argvs).toContainEqual(['clear', 'service', 'Secretless: KEY1', 'account', 'mcp/client/server/KEY1']);
      expect(argvs).toContainEqual(['clear', 'service', 'secretless', 'account', 'mcp/client/server/KEY1']);

      const indexPath = path.join(dir, 'keychain-index.json');
      const updatedIndex = JSON.parse(fs.readFileSync(indexPath, 'utf-8'));
      expect(updatedIndex).not.toContain('mcp/client/server/KEY1');
    });

    it('returns false when secret-tool fails', async () => {
      recorder.setMode({ kind: 'fail', status: 1, stderr: 'secret-tool: no such collection\n' });
      const result = await backend.delete('nonexistent');
      expect(result).toBe(false);
    });
  });

  describe('healthCheck()', () => {
    it('returns healthy when secret-tool is found', async () => {
      // `which` resolves the recorder by its absolute path.
      const health = await backend.healthCheck();
      expect(health.healthy).toBe(true);
      expect(health.message).toContain('secret-tool available');
    });

    it('returns unhealthy when secret-tool is not found', async () => {
      const absent = new LinuxKeychainBackend({ storeDir: dir }, { secretToolProgram: 'secret-tool-that-is-not-installed-anywhere' });
      const health = await absent.healthCheck();
      expect(health.healthy).toBe(false);
      expect(health.message).toContain('secret-tool not found');
    });
  });
});
