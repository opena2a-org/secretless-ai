import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { SecretStore } from './secret-store';
import { LocalBackend } from './backends/local';

describe('SecretStore', () => {
  let tmpDir: string;
  let store: SecretStore;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-store-test-'));
    const backend = new LocalBackend({ storeDir: tmpDir, key: 'test-key' });
    store = new SecretStore({ backend });
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('stores and retrieves a secret', async () => {
    await store.setSecret('GITHUB_TOKEN', 'ghp_abc123');
    const value = await store.getSecret('GITHUB_TOKEN');
    expect(value).toBe('ghp_abc123');
  });

  it('returns undefined for missing secret', async () => {
    const value = await store.getSecret('NONEXISTENT');
    expect(value).toBeUndefined();
  });

  it('lists stored secret names sorted', async () => {
    await store.setSecret('ZEBRA_KEY', 'z');
    await store.setSecret('ALPHA_KEY', 'a');
    await store.setSecret('MID_KEY', 'm');
    const names = await store.listSecrets();
    expect(names).toEqual(['ALPHA_KEY', 'MID_KEY', 'ZEBRA_KEY']);
  });

  it('returns empty list when no secrets stored', async () => {
    const names = await store.listSecrets();
    expect(names).toEqual([]);
  });

  it('removes a secret', async () => {
    await store.setSecret('TO_DELETE', 'val');
    const removed = await store.removeSecret('TO_DELETE');
    expect(removed).toBe(true);
    const value = await store.getSecret('TO_DELETE');
    expect(value).toBeUndefined();
  });

  it('returns false when removing nonexistent secret', async () => {
    const removed = await store.removeSecret('NONEXISTENT');
    expect(removed).toBe(false);
  });

  it('overwrites existing secret', async () => {
    await store.setSecret('MY_KEY', 'old');
    await store.setSecret('MY_KEY', 'new');
    const value = await store.getSecret('MY_KEY');
    expect(value).toBe('new');
  });

  it('loads all secrets as key-value pairs', async () => {
    await store.setSecret('A', '1');
    await store.setSecret('B', '2');
    const secrets = await store.loadSecrets();
    expect(secrets).toEqual({ A: '1', B: '2' });
  });

  it('loads filtered secrets with only option', async () => {
    await store.setSecret('A', '1');
    await store.setSecret('B', '2');
    await store.setSecret('C', '3');
    const secrets = await store.loadSecrets(['A', 'C']);
    expect(secrets).toEqual({ A: '1', C: '3' });
  });

  it('loads filtered secrets case-insensitively', async () => {
    await store.setSecret('SHODAN_KEY', 'sk-123');
    await store.setSecret('ANTHROPIC_API_KEY', 'ant-456');
    await store.setSecret('OTHER_KEY', 'other');
    const secrets = await store.loadSecrets(['shodan_key', 'anthropic_api_key']);
    expect(secrets).toEqual({ SHODAN_KEY: 'sk-123', ANTHROPIC_API_KEY: 'ant-456' });
  });

  it('rejects invalid secret names', async () => {
    await expect(store.setSecret('my secret', 'val')).rejects.toThrow('Invalid secret name');
    await expect(store.setSecret('../traversal', 'val')).rejects.toThrow('Invalid secret name');
    await expect(store.setSecret('', 'val')).rejects.toThrow('Invalid secret name');
  });

  it('accepts valid secret names with dashes and underscores', async () => {
    await store.setSecret('MY_API-KEY', 'val');
    const value = await store.getSecret('MY_API-KEY');
    expect(value).toBe('val');
  });

  it('isolates from MCP secrets (different prefix)', async () => {
    // Store a secret via the store
    await store.setSecret('TOKEN', 'store-value');

    // Verify it's stored under secret/ prefix by checking the backend directly
    const backend = new LocalBackend({ storeDir: tmpDir, key: 'test-key' });
    const resolved = await backend.resolve('secret/TOKEN');
    expect(resolved['secret/TOKEN']).toBe('store-value');

    // Verify MCP prefix returns nothing
    const mcpResolved = await backend.resolve('mcp');
    expect(Object.keys(mcpResolved)).toHaveLength(0);
  });

  describe('backendName (scope disclosure)', () => {
    it('exposes the active backend name', () => {
      expect(store.backendName).toBe('local');
    });

    it('unwraps the cache decorator so disclosure shows the real backend', () => {
      const cached = new SecretStore({
        backend: {
          name: 'cached(keychain-macos)',
          resolve: async () => ({}),
          store: async () => {},
          delete: async () => false,
        },
      });
      expect(cached.backendName).toBe('keychain-macos');
    });
  });
});

describe('loadSecrets — a requested name that resolves to nothing (issue #110)', () => {
  /**
   * One root cause behind all three reported failure modes: loadSecrets filtered
   * what the backend RETURNED and never checked what it was ASKED for, so an
   * unmatched name left no trace and was indistinguishable downstream from a
   * name nobody requested.
   */
  function storeWith(entries: Record<string, string>) {
    return new SecretStore({
      backend: {
        name: 'fake',
        resolve: async () => ({ ...entries }),
        store: async () => {},
        delete: async () => false,
      },
    });
  }

  const POPULATED = { 'secret/ANTHROPIC_API_KEY': 'v1', 'secret/DATABASE_URL': 'v2' };

  it('mode 2: a PARTIALLY matched list is an error, not a silent short run', async () => {
    // The dangerous one. `--only DATABASE_URL,DATABSE_PASSWORD` used to run the
    // job with one secret missing and exit 0.
    const store = storeWith(POPULATED);
    await expect(store.loadSecrets(['ANTHROPIC_API_KEY', 'NOT_IN_THE_VAULT']))
      .rejects.toThrow(/NOT_IN_THE_VAULT/);
  });

  it('mode 1: no name matched names the filter, not the backend', async () => {
    const store = storeWith(POPULATED);
    let message = '';
    try {
      await store.loadSecrets(['NOT_IN_THE_VAULT']);
    } catch (e) {
      message = (e as Error).message;
    }
    expect(message).toMatch(/NOT_IN_THE_VAULT/);
    // The old path blamed the backend for what was a filter miss.
    expect(message).not.toMatch(/backend failure/i);
  });

  it('mode 3: an EMPTY store still reports the unmatched name', async () => {
    // Reachable with no user error at all — a fresh machine or CI runner.
    const store = storeWith({});
    await expect(store.loadSecrets(['ANY_NAME_AT_ALL']))
      .rejects.toThrow(/ANY_NAME_AT_ALL/);
  });

  it('names EVERY unmatched entry, not just the first', async () => {
    const store = storeWith(POPULATED);
    let message = '';
    try {
      await store.loadSecrets(['MISSING_ONE', 'ANTHROPIC_API_KEY', 'MISSING_TWO']);
    } catch (e) {
      message = (e as Error).message;
    }
    expect(message).toMatch(/MISSING_ONE/);
    expect(message).toMatch(/MISSING_TWO/);
  });

  it('carries Verify and Fix lines, like the rest of the CLI', async () => {
    const store = storeWith(POPULATED);
    let message = '';
    try {
      await store.loadSecrets(['NOT_IN_THE_VAULT']);
    } catch (e) {
      message = (e as Error).message;
    }
    expect(message).toMatch(/Verify:/);
    expect(message).toMatch(/Fix:/);
    expect(message).toMatch(/secret list/);
  });

  it('suggests a near miss, since the whole class is typos', async () => {
    const store = storeWith(POPULATED);
    let message = '';
    try {
      await store.loadSecrets(['DATABASE_UR']);
    } catch (e) {
      message = (e as Error).message;
    }
    expect(message).toMatch(/DATABASE_URL/);
  });

  it('never leaks a secret VALUE into the error', async () => {
    const store = storeWith(POPULATED);
    let message = '';
    try {
      await store.loadSecrets(['NOT_IN_THE_VAULT']);
    } catch (e) {
      message = (e as Error).message;
    }
    expect(message).not.toContain('v1');
    expect(message).not.toContain('v2');
  });

  // ---- controls: the working paths must keep working ----

  it('CONTROL: a fully matched list resolves normally', async () => {
    const store = storeWith(POPULATED);
    const out = await store.loadSecrets(['ANTHROPIC_API_KEY']);
    expect(out).toEqual({ ANTHROPIC_API_KEY: 'v1' });
  });

  it('CONTROL: matching stays case-insensitive', async () => {
    const store = storeWith(POPULATED);
    const out = await store.loadSecrets(['anthropic_api_key']);
    expect(out).toEqual({ ANTHROPIC_API_KEY: 'v1' });
  });

  it('CONTROL: no --only on a populated store returns everything', async () => {
    const store = storeWith(POPULATED);
    const out = await store.loadSecrets();
    expect(Object.keys(out).sort()).toEqual(['ANTHROPIC_API_KEY', 'DATABASE_URL']);
  });

  it('CONTROL: no --only on an EMPTY store is not an error', async () => {
    // Only a REQUESTED name that went unmatched is an error. Asking for
    // everything and getting nothing is the pre-existing warn-and-continue path.
    const store = storeWith({});
    await expect(store.loadSecrets()).resolves.toEqual({});
  });

  it('CONTROL: a duplicated request is not reported as unmatched', async () => {
    const store = storeWith(POPULATED);
    const out = await store.loadSecrets(['ANTHROPIC_API_KEY', 'anthropic_api_key']);
    expect(out).toEqual({ ANTHROPIC_API_KEY: 'v1' });
  });
});

describe('near-miss hint work is bounded (CI review finding, measured)', () => {
  function storeOf(names: string[]) {
    const entries: Record<string, string> = {};
    for (const n of names) entries[`secret/${n}`] = 'v';
    return new SecretStore({
      backend: {
        name: 'fake',
        resolve: async () => entries,
        store: async () => {},
        delete: async () => false,
      },
    });
  }

  it('stays fast when stored names SHARE A LONG PREFIX', async () => {
    // This is the shape that matters, and the one an earlier benchmark missed.
    // Maximally-different names exit on the first row of the table, so they
    // never exercise the expensive path; names that look alike — which stored
    // secret names do — keep the band under the threshold the whole way.
    // Measured: 7814ms unbounded, 840ms with a row cutoff alone, 378ms banded.
    const names: string[] = [];
    for (let i = 0; i < 5000; i++) names.push('A'.repeat(60) + String(i).padStart(4, '0'));
    const requested: string[] = [];
    for (let i = 0; i < 100; i++) requested.push('A'.repeat(60) + String(9000 + i).padStart(4, '0'));

    const started = Date.now();
    await expect(storeOf(names).loadSecrets(requested)).rejects.toThrow();
    expect(Date.now() - started).toBeLessThan(1500);
  });

  it('CONTROL: a real near miss is still suggested', async () => {
    // The band must not be so tight that it stops finding typos.
    let message = '';
    try {
      await storeOf(['DATABASE_URL']).loadSecrets(['DATABSE_URL']);
    } catch (e) {
      message = (e as Error).message;
    }
    expect(message).toContain('DATABASE_URL');
  });

  it('CONTROL: a distance-2 typo is still within the threshold', async () => {
    let message = '';
    try {
      await storeOf(['GITHUB_TOKEN']).loadSecrets(['GITHB_TOKN']);
    } catch (e) {
      message = (e as Error).message;
    }
    expect(message).toContain('GITHUB_TOKEN');
  });

  it('CONTROL: a near miss LATE in a long shared prefix is still found', async () => {
    // Banding is indexed off the diagonal, so an edit far along the string is
    // exactly where a wrong band would clip the answer.
    const base = 'A'.repeat(50) + 'DATABASE_URL';
    let message = '';
    try {
      await storeOf([base]).loadSecrets([base.slice(0, -1) + 'X']);
    } catch (e) {
      message = (e as Error).message;
    }
    expect(message).toContain(base);
  });

  it('does NOT suggest a name three edits away', async () => {
    // Pins the threshold from the other side: without this, widening the band
    // to "fix" a clipped near miss would go unnoticed.
    const base = 'A'.repeat(50) + 'DATABASE_URL';
    let message = '';
    try {
      await storeOf([base]).loadSecrets([base.slice(0, -3) + 'XYZ']);
    } catch (e) {
      message = (e as Error).message;
    }
    expect(message).not.toContain('Did you mean');
  });
});
