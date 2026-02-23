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
});
