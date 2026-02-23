import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { McpVault } from './vault';

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-mcp-vault-test-'));
}

function cleanup(dir: string): void {
  fs.rmSync(dir, { recursive: true, force: true });
}

describe('McpVault', () => {
  let dir: string;

  beforeEach(() => { dir = tmpDir(); });
  afterEach(() => { cleanup(dir); });

  it('stores and retrieves secrets for a server', async () => {
    const vault = new McpVault({ storeDir: dir, key: 'test-key', backendType: 'local' });

    await vault.storeServerSecrets('claude-desktop', 'my-server', {
      ANTHROPIC_API_KEY: 'sk-ant-123',
      DATABASE_URL: 'postgres://localhost/db',
    });

    const secrets = await vault.getServerSecrets('claude-desktop', 'my-server');
    expect(secrets).toEqual({
      ANTHROPIC_API_KEY: 'sk-ant-123',
      DATABASE_URL: 'postgres://localhost/db',
    });
  });

  it('returns empty for non-existent server', async () => {
    const vault = new McpVault({ storeDir: dir, key: 'test-key', backendType: 'local' });

    const secrets = await vault.getServerSecrets('claude-desktop', 'no-such-server');
    expect(secrets).toEqual({});
  });

  it('stores secrets for multiple servers independently', async () => {
    const vault = new McpVault({ storeDir: dir, key: 'test-key', backendType: 'local' });

    await vault.storeServerSecrets('cursor', 'server-a', {
      API_KEY: 'key-a',
    });
    await vault.storeServerSecrets('cursor', 'server-b', {
      API_KEY: 'key-b',
    });

    const secretsA = await vault.getServerSecrets('cursor', 'server-a');
    expect(secretsA).toEqual({ API_KEY: 'key-a' });

    const secretsB = await vault.getServerSecrets('cursor', 'server-b');
    expect(secretsB).toEqual({ API_KEY: 'key-b' });
  });

  it('stores secrets for multiple clients independently', async () => {
    const vault = new McpVault({ storeDir: dir, key: 'test-key', backendType: 'local' });

    await vault.storeServerSecrets('claude-desktop', 'shared-server', {
      TOKEN: 'claude-token',
    });
    await vault.storeServerSecrets('cursor', 'shared-server', {
      TOKEN: 'cursor-token',
    });

    const claudeSecrets = await vault.getServerSecrets('claude-desktop', 'shared-server');
    expect(claudeSecrets).toEqual({ TOKEN: 'claude-token' });

    const cursorSecrets = await vault.getServerSecrets('cursor', 'shared-server');
    expect(cursorSecrets).toEqual({ TOKEN: 'cursor-token' });
  });

  it('overwrites existing secrets on re-store', async () => {
    const vault = new McpVault({ storeDir: dir, key: 'test-key', backendType: 'local' });

    await vault.storeServerSecrets('claude-desktop', 'my-server', {
      API_KEY: 'old-key',
      OTHER: 'other-value',
    });

    await vault.storeServerSecrets('claude-desktop', 'my-server', {
      API_KEY: 'new-key',
      EXTRA: 'extra-value',
    });

    const secrets = await vault.getServerSecrets('claude-desktop', 'my-server');
    // The new store should contain the new secrets.
    // Old keys not in the new store call may persist (store is additive per key).
    expect(secrets.API_KEY).toBe('new-key');
    expect(secrets.EXTRA).toBe('extra-value');
  });

  it('removes secrets for a server', async () => {
    const vault = new McpVault({ storeDir: dir, key: 'test-key', backendType: 'local' });

    await vault.storeServerSecrets('cursor', 'server-a', {
      KEY1: 'val1',
      KEY2: 'val2',
    });
    await vault.storeServerSecrets('cursor', 'server-b', {
      KEY3: 'val3',
    });

    await vault.removeServerSecrets('cursor', 'server-a');

    const removedSecrets = await vault.getServerSecrets('cursor', 'server-a');
    expect(removedSecrets).toEqual({});

    // server-b should be unaffected
    const remainingSecrets = await vault.getServerSecrets('cursor', 'server-b');
    expect(remainingSecrets).toEqual({ KEY3: 'val3' });
  });

  it('lists all stored server entries', async () => {
    const vault = new McpVault({ storeDir: dir, key: 'test-key', backendType: 'local' });

    await vault.storeServerSecrets('claude-desktop', 'server-1', {
      KEY_A: 'a',
      KEY_B: 'b',
    });
    await vault.storeServerSecrets('cursor', 'server-2', {
      KEY_C: 'c',
    });
    await vault.storeServerSecrets('cursor', 'server-3', {
      KEY_D: 'd',
      KEY_E: 'e',
      KEY_F: 'f',
    });

    const entries = await vault.listEntries();

    expect(entries).toHaveLength(3);

    const entry1 = entries.find(e => e.client === 'claude-desktop' && e.server === 'server-1');
    expect(entry1).toBeDefined();
    expect(entry1!.keyCount).toBe(2);

    const entry2 = entries.find(e => e.client === 'cursor' && e.server === 'server-2');
    expect(entry2).toBeDefined();
    expect(entry2!.keyCount).toBe(1);

    const entry3 = entries.find(e => e.client === 'cursor' && e.server === 'server-3');
    expect(entry3).toBeDefined();
    expect(entry3!.keyCount).toBe(3);
  });

  it('encrypts data on disk (no plaintext secrets in raw file)', async () => {
    const vault = new McpVault({ storeDir: dir, key: 'test-key', backendType: 'local' });

    const sensitiveValue = 'super-secret-api-key-12345';
    await vault.storeServerSecrets('claude-desktop', 'my-server', {
      SENSITIVE: sensitiveValue,
    });

    const storePath = path.join(dir, 'secrets.enc');
    expect(fs.existsSync(storePath)).toBe(true);

    const raw = fs.readFileSync(storePath);
    // Raw encrypted file should not contain plaintext
    expect(raw.toString('utf-8')).not.toContain(sensitiveValue);
    expect(raw.toString('utf-8')).not.toContain('SENSITIVE');
    // Should have IV (16) + tag (16) + ciphertext
    expect(raw.length).toBeGreaterThan(32);
  });
});
