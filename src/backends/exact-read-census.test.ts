/**
 * `resolve(path, { exact: true })` names one entry: it returns `{ [path]: value }`
 * when an entry is stored under exactly `path` and `{}` otherwise, and it reads
 * the value of no other entry (`ResolveOptions` in ./types). These cells check
 * every backend that resolves, and the cache layer, over a store holding
 * `secret/X` and `secret/X/child`: an entry, and an entry under it.
 *
 * (i)  With both stored, the exact read of `secret/X` returns that entry and
 *      reads only its value.
 * (ii) With only `secret/X/child` stored, the same read returns {} and reads
 *      no value.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as child_process from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import type { ResolveOptions, WritableSecretBackend } from './types';
import { LocalBackend } from './local';
import { MacOSKeychainBackend } from './keychain-macos';
import { LinuxKeychainBackend } from './keychain-linux';
import { OnePasswordBackend } from './onepassword';
import { VaultBackend } from './vault';
import { GCPSecretManagerBackend } from './gcp-sm';
import { CachedBackend } from './cache';
import {
  makeSecurityRecorder,
  makeSecretToolRecorder,
  type Recorder,
  type RecordedCall,
} from './child-recorder.test-support';
import { fakeSecretManager, type FakeSecretManager } from './gcp-sm-fake.test-support';

// The 1Password cells answer `op` through execFileSync. Every other export is
// the real module: the keychain backends start their recorder programs through
// it, and execFileSync keeps its real implementation outside those cells.
vi.mock('child_process', async (importOriginal) => {
  const actual = await importOriginal<typeof import('child_process')>();
  return { ...actual, execFileSync: vi.fn(actual.execFileSync) };
});

const X = 'secret/X';
const CHILD = 'secret/X/child';
const VALUES: Record<string, string> = { [X]: 'value-of-x', [CHILD]: 'value-of-child' };

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-exact-census-'));
}

/**
 * The entries a keychain program was asked to read: the account of each `read`
 * call. Any other call is listed by its argv, so a cell expecting one read also
 * sees a second call of any kind.
 */
function childReads(calls: RecordedCall[], read: string, accountFlag: string): string[] {
  return calls.map((c) => {
    const i = c.argv.indexOf(accountFlag);
    return c.argv[0] === read && i > 0 ? c.argv[i + 1] : c.argv.join(' ');
  });
}

describe('an exact read returns the entry at its path and reads no other value', () => {
  describe('local', () => {
    let dir: string;

    beforeEach(() => {
      dir = tmpDir();
    });
    afterEach(() => {
      fs.rmSync(dir, { recursive: true, force: true });
    });

    // The store is one file, decrypted whole: the values a read hands out are
    // the entries it returns, so the returned record is the read.
    async function holding(keys: string[]): Promise<LocalBackend> {
      const backend = new LocalBackend({ storeDir: dir, key: 'fixed-test-key-material' });
      for (const key of keys) await backend.store(key, VALUES[key]);
      return backend;
    }

    it("(i) resolve('secret/X', { exact: true }) over secret/X and secret/X/child returns only secret/X", async () => {
      const backend = await holding([X, CHILD]);
      expect(await backend.resolve(X, { exact: true })).toEqual({ [X]: VALUES[X] });
    });

    it("(ii) resolve('secret/X', { exact: true }) over secret/X/child alone returns {}", async () => {
      const backend = await holding([CHILD]);
      expect(await backend.resolve(X, { exact: true })).toEqual({});
    });
  });

  describe('keychain-macos', () => {
    let dir: string;
    let recorder: Recorder;

    beforeEach(() => {
      dir = tmpDir();
      recorder = makeSecurityRecorder();
    });
    afterEach(() => {
      fs.rmSync(dir, { recursive: true, force: true });
      recorder.cleanup();
    });

    /** The backend over the recorder holding `keys`, and the reads made after they were stored. */
    async function holding(keys: string[]) {
      const backend = new MacOSKeychainBackend({ storeDir: dir }, { securityProgram: recorder.program });
      for (const key of keys) await backend.store(key, VALUES[key]);
      const from = recorder.calls().length;
      return { backend, reads: () => childReads(recorder.calls().slice(from), 'find-generic-password', '-a') };
    }

    it("(i) resolve('secret/X', { exact: true }) over secret/X and secret/X/child returns only secret/X, and one find-generic-password runs, for secret/X", async () => {
      const { backend, reads } = await holding([X, CHILD]);
      const result = await backend.resolve(X, { exact: true });
      expect({ result, reads: reads() }).toEqual({ result: { [X]: VALUES[X] }, reads: [X] });
    });

    it("(ii) resolve('secret/X', { exact: true }) over secret/X/child alone returns {} and starts no security call", async () => {
      const { backend, reads } = await holding([CHILD]);
      const result = await backend.resolve(X, { exact: true });
      expect({ result, reads: reads() }).toEqual({ result: {}, reads: [] });
    });
  });

  describe('keychain-linux', () => {
    let dir: string;
    let recorder: Recorder;

    beforeEach(() => {
      dir = tmpDir();
      recorder = makeSecretToolRecorder();
    });
    afterEach(() => {
      fs.rmSync(dir, { recursive: true, force: true });
      recorder.cleanup();
    });

    /** The backend over the recorder holding `keys`, and the reads made after they were stored. */
    async function holding(keys: string[]) {
      const backend = new LinuxKeychainBackend({ storeDir: dir }, { secretToolProgram: recorder.program });
      for (const key of keys) await backend.store(key, VALUES[key]);
      const from = recorder.calls().length;
      return { backend, reads: () => childReads(recorder.calls().slice(from), 'lookup', 'account') };
    }

    it("(i) resolve('secret/X', { exact: true }) over secret/X and secret/X/child returns only secret/X, and one secret-tool lookup runs, for secret/X", async () => {
      const { backend, reads } = await holding([X, CHILD]);
      const result = await backend.resolve(X, { exact: true });
      expect({ result, reads: reads() }).toEqual({ result: { [X]: VALUES[X] }, reads: [X] });
    });

    it("(ii) resolve('secret/X', { exact: true }) over secret/X/child alone returns {} and starts no secret-tool call", async () => {
      const { backend, reads } = await holding([CHILD]);
      const result = await backend.resolve(X, { exact: true });
      expect({ result, reads: reads() }).toEqual({ result: {}, reads: [] });
    });
  });

  describe('1password', () => {
    const VAULT_ID = 'census-vault';
    let items: { id: string; title: string; password: string }[] = [];
    const reads: string[] = [];
    let itemGets = 0;

    beforeEach(() => {
      items = [];
      reads.length = 0;
      itemGets = 0;
      vi.mocked(child_process.execFileSync).mockImplementation(((cmd: string, args: string[]) => {
        if (cmd !== 'op') throw new Error(`census stub: refused ${cmd}`);
        const sub = `${args[0]} ${args[1]}`;
        if (sub === 'vault get') return JSON.stringify({ id: VAULT_ID });
        if (sub === 'item list') return JSON.stringify(items.map(({ id, title }) => ({ id, title })));
        if (sub === 'item get') {
          itemGets++;
          const item = items.find((i) => i.id === args[2]);
          if (!item) throw new Error('item not found');
          reads.push(item.title);
          return JSON.stringify({ value: item.password });
        }
        throw new Error(`census stub: no answer for op ${sub}`);
      }) as unknown as typeof child_process.execFileSync);
    });
    afterEach(() => {
      vi.mocked(child_process.execFileSync).mockReset();
    });

    /** A vault holding one item per key, titled with the key. */
    function holding(keys: string[]): OnePasswordBackend {
      items = keys.map((title, i) => ({ id: `item-${i}`, title, password: VALUES[title] }));
      return new OnePasswordBackend();
    }

    it("(i) resolve('secret/X', { exact: true }) over secret/X and secret/X/child returns only secret/X, and one item get runs, for secret/X", async () => {
      const backend = holding([X, CHILD]);
      const result = await backend.resolve(X, { exact: true });
      expect({ result, reads, itemGets }).toEqual({ result: { [X]: VALUES[X] }, reads: [X], itemGets: 1 });
    });

    it("(ii) resolve('secret/X', { exact: true }) over secret/X/child alone returns {} and runs no item get", async () => {
      const backend = holding([CHILD]);
      const result = await backend.resolve(X, { exact: true });
      expect({ result, reads, itemGets }).toEqual({ result: {}, reads: [], itemGets: 0 });
    });
  });

  describe('vault', () => {
    const ADDR = 'http://127.0.0.1:8200';
    let stored: Record<string, string> = {};
    const reads: string[] = [];
    const requests: string[] = [];

    /** A KV v2 mount at `secret/` holding `stored`, answering GET and LIST. */
    const kv = async (input: string, init?: { method?: string }) => {
      const url = new URL(input);
      if (url.origin !== ADDR) throw new Error(`census stub: refused a request to ${url.origin}`);
      const method = init?.method ?? 'GET';
      requests.push(`${method} ${url.pathname}`);
      const data = /^\/v1\/secret\/data\/(.+)$/.exec(url.pathname);
      if (data && method === 'GET') {
        const key = data[1].split('/').map(decodeURIComponent).join('/');
        if (!(key in stored)) return { ok: false, status: 404, json: async () => ({}), text: async () => '' };
        reads.push(key);
        return { ok: true, status: 200, json: async () => ({ data: { data: { value: stored[key] } } }), text: async () => '' };
      }
      const meta = /^\/v1\/secret\/metadata\/(.+)$/.exec(url.pathname);
      if (meta && method === 'LIST') {
        const prefix = `${meta[1].split('/').map(decodeURIComponent).join('/')}/`;
        const children = new Set<string>();
        for (const key of Object.keys(stored)) {
          if (!key.startsWith(prefix)) continue;
          const rest = key.slice(prefix.length);
          children.add(rest.includes('/') ? `${rest.split('/')[0]}/` : rest);
        }
        if (children.size === 0) return { ok: false, status: 404, json: async () => ({}), text: async () => '' };
        return { ok: true, status: 200, json: async () => ({ data: { keys: [...children] } }), text: async () => '' };
      }
      throw new Error(`census stub: no route for ${method} ${url.pathname}`);
    };

    beforeEach(() => {
      stored = {};
      reads.length = 0;
      requests.length = 0;
      vi.stubGlobal('fetch', vi.fn(kv));
    });
    afterEach(() => {
      vi.unstubAllGlobals();
    });

    function holding(keys: string[]): VaultBackend {
      stored = Object.fromEntries(keys.map((key) => [key, VALUES[key]]));
      return new VaultBackend({ addr: ADDR, token: 'census-placeholder' });
    }

    const lists = () => requests.filter((r) => r.startsWith('LIST '));

    it("(i) resolve('secret/X', { exact: true }) over secret/X and secret/X/child returns only secret/X, reads only its value, and sends no LIST", async () => {
      const backend = holding([X, CHILD]);
      const result = await backend.resolve(X, { exact: true });
      expect({ result, reads, lists: lists() }).toEqual({ result: { [X]: VALUES[X] }, reads: [X], lists: [] });
    });

    it("(ii) resolve('secret/X', { exact: true }) over secret/X/child alone returns {}, reads no value, and sends no LIST", async () => {
      const backend = holding([CHILD]);
      const result = await backend.resolve(X, { exact: true });
      expect({ result, reads, lists: lists() }).toEqual({ result: {}, reads: [], lists: [] });
    });
  });

  describe('gcp-sm', () => {
    const PROJECT = 'census-project';
    let project: FakeSecretManager;

    beforeEach(() => {
      project = fakeSecretManager(PROJECT);
      vi.stubGlobal('fetch', vi.fn(project.fetch));
    });
    afterEach(() => {
      vi.unstubAllGlobals();
    });

    /** A backend over the fake project whose token is already held, so no sign-in runs. */
    function backend(): GCPSecretManagerBackend {
      const b = new GCPSecretManagerBackend({ projectId: PROJECT });
      Object.assign(b, { accessToken: 'census-placeholder', tokenExpiry: Date.now() + 3_600_000 });
      return b;
    }

    /** The project holding `keys`, stored through the backend, and the reads a new backend makes after. */
    async function holding(keys: string[]) {
      const writer = backend();
      const keyOfId: Record<string, string> = {};
      for (const key of keys) {
        const before = new Set(project.secrets.keys());
        await writer.store(key, VALUES[key]);
        for (const id of project.secrets.keys()) if (!before.has(id)) keyOfId[id] = key;
      }
      project.valueReads.length = 0;
      project.requests.length = 0;
      return { backend: backend(), reads: () => project.valueReads.map((id) => keyOfId[id] ?? id) };
    }

    const lists = () => project.requests.filter((r) => r.startsWith(`GET /v1/projects/${PROJECT}/secrets?`));

    it("(i) resolve('secret/X', { exact: true }) over secret/X and secret/X/child returns only secret/X, reads only its value, and lists nothing", async () => {
      const { backend: reader, reads } = await holding([X, CHILD]);
      const result = await reader.resolve(X, { exact: true });
      expect({ result, reads: reads(), lists: lists() }).toEqual({ result: { [X]: VALUES[X] }, reads: [X], lists: [] });
    });

    it("(ii) resolve('secret/X', { exact: true }) over secret/X/child alone returns {}, reads no value, and lists nothing", async () => {
      const { backend: reader, reads } = await holding([CHILD]);
      const result = await reader.resolve(X, { exact: true });
      expect({ result, reads: reads(), lists: lists() }).toEqual({ result: {}, reads: [], lists: [] });
    });
  });

  describe('cache', () => {
    let dir: string;
    let cacheDir: string;
    let recorder: Recorder;

    beforeEach(() => {
      dir = tmpDir();
      cacheDir = tmpDir();
      recorder = makeSecurityRecorder();
    });
    afterEach(() => {
      fs.rmSync(dir, { recursive: true, force: true });
      fs.rmSync(cacheDir, { recursive: true, force: true });
      recorder.cleanup();
    });

    /**
     * The cache over the macOS keychain backend on the recorder, as the factory
     * wraps a keychain backend, holding `keys`. `calls` records each read the
     * cache passes to the backend it wraps; `reads` are the entries the
     * keychain program was asked for since `mark()`.
     */
    async function holding(keys: string[]) {
      const keychain = new MacOSKeychainBackend({ storeDir: dir }, { securityProgram: recorder.program });
      for (const key of keys) await keychain.store(key, VALUES[key]);
      const calls: { path: string; options?: ResolveOptions }[] = [];
      const inner: WritableSecretBackend = {
        name: keychain.name,
        resolve: (p, options) => {
          calls.push({ path: p, options });
          return keychain.resolve(p, options);
        },
        store: (key, value) => keychain.store(key, value),
        delete: (key) => keychain.delete(key),
        healthCheck: () => keychain.healthCheck(),
      };
      let from = recorder.calls().length;
      return {
        cached: new CachedBackend(inner, { ttlMs: 60_000, storeDir: cacheDir }),
        calls,
        reads: () => childReads(recorder.calls().slice(from), 'find-generic-password', '-a'),
        mark: () => {
          from = recorder.calls().length;
          calls.length = 0;
        },
      };
    }

    it("(i) resolve('secret/X', { exact: true }) over secret/X and secret/X/child returns only secret/X, reads only its value, and passes the option to the backend it wraps", async () => {
      const s = await holding([X, CHILD]);
      const result = await s.cached.resolve(X, { exact: true });
      expect({ result, reads: s.reads(), calls: s.calls }).toEqual({
        result: { [X]: VALUES[X] },
        reads: [X],
        calls: [{ path: X, options: { exact: true } }],
      });
    });

    it("(ii) resolve('secret/X', { exact: true }) over secret/X/child alone returns {} and reads no value", async () => {
      const s = await holding([CHILD]);
      const result = await s.cached.resolve(X, { exact: true });
      expect({ result, reads: s.reads() }).toEqual({ result: {}, reads: [] });
    });

    it('after a prefix read of secret/X cached both entries, the exact read of secret/X returns only secret/X and makes no inner call', async () => {
      const s = await holding([X, CHILD]);
      expect(await s.cached.resolve(X)).toEqual({ [X]: VALUES[X], [CHILD]: VALUES[CHILD] });
      s.mark();
      const result = await s.cached.resolve(X, { exact: true });
      expect({ result, calls: s.calls, reads: s.reads() }).toEqual({ result: { [X]: VALUES[X] }, calls: [], reads: [] });
    });

    it('after an exact read of secret/X cached that entry, a prefix read of secret/X asks the backend it wraps and returns both entries', async () => {
      const s = await holding([X, CHILD]);
      await s.cached.resolve(X, { exact: true });
      s.mark();
      const result = await s.cached.resolve(X);
      expect({ result, calls: s.calls }).toEqual({
        result: { [X]: VALUES[X], [CHILD]: VALUES[CHILD] },
        calls: [{ path: X, options: undefined }],
      });
    });
  });
});
