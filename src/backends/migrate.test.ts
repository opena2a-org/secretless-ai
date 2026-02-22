import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { LocalBackend } from './local';
import { migrateSecrets } from './migrate';

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-migrate-test-'));
}

function cleanup(dir: string): void {
  fs.rmSync(dir, { recursive: true, force: true });
}

describe('migrateSecrets', () => {
  let sourceDir: string;
  let destDir: string;

  beforeEach(() => {
    sourceDir = tmpDir();
    destDir = tmpDir();
  });

  afterEach(() => {
    cleanup(sourceDir);
    cleanup(destDir);
  });

  it('migrates all secrets from source to destination', async () => {
    const source = new LocalBackend({ storeDir: sourceDir, key: 'source-key' });
    const dest = new LocalBackend({ storeDir: destDir, key: 'dest-key' });

    // Store secrets in source
    await source.store('mcp/client/server/KEY1', 'value1');
    await source.store('mcp/client/server/KEY2', 'value2');
    await source.store('mcp/other/server/KEY3', 'value3');

    const result = await migrateSecrets(source, dest);

    expect(result.migrated).toBe(3);
    expect(result.failed).toBe(0);
    expect(result.errors).toHaveLength(0);

    // Verify destination has the secrets
    const destSecrets = await dest.resolve('mcp');
    expect(destSecrets['mcp/client/server/KEY1']).toBe('value1');
    expect(destSecrets['mcp/client/server/KEY2']).toBe('value2');
    expect(destSecrets['mcp/other/server/KEY3']).toBe('value3');
  });

  it('preserves source secrets when deleteFromSource is false', async () => {
    const source = new LocalBackend({ storeDir: sourceDir, key: 'source-key' });
    const dest = new LocalBackend({ storeDir: destDir, key: 'dest-key' });

    await source.store('mcp/client/server/KEY', 'value');

    await migrateSecrets(source, dest, { deleteFromSource: false });

    // Source should still have the secret
    const sourceSecrets = await source.resolve('mcp');
    expect(sourceSecrets['mcp/client/server/KEY']).toBe('value');
  });

  it('deletes from source when deleteFromSource is true', async () => {
    const source = new LocalBackend({ storeDir: sourceDir, key: 'source-key' });
    const dest = new LocalBackend({ storeDir: destDir, key: 'dest-key' });

    await source.store('mcp/client/server/KEY', 'value');

    await migrateSecrets(source, dest, { deleteFromSource: true });

    // Source should no longer have the secret
    const sourceSecrets = await source.resolve('mcp');
    expect(sourceSecrets).toEqual({});

    // Destination should have it
    const destSecrets = await dest.resolve('mcp');
    expect(destSecrets['mcp/client/server/KEY']).toBe('value');
  });

  it('returns zero counts when no secrets found', async () => {
    const source = new LocalBackend({ storeDir: sourceDir, key: 'source-key' });
    const dest = new LocalBackend({ storeDir: destDir, key: 'dest-key' });

    const result = await migrateSecrets(source, dest);

    expect(result.migrated).toBe(0);
    expect(result.failed).toBe(0);
  });

  it('uses custom prefix', async () => {
    const source = new LocalBackend({ storeDir: sourceDir, key: 'source-key' });
    const dest = new LocalBackend({ storeDir: destDir, key: 'dest-key' });

    await source.store('mcp/client/server/KEY', 'mcp-val');
    await source.store('other/path/KEY', 'other-val');

    const result = await migrateSecrets(source, dest, { prefix: 'other' });

    expect(result.migrated).toBe(1);

    // Only 'other' prefix should have been migrated
    const destSecrets = await dest.resolve('other');
    expect(destSecrets['other/path/KEY']).toBe('other-val');

    // mcp prefix should not be in destination
    const mcpSecrets = await dest.resolve('mcp');
    expect(Object.keys(mcpSecrets)).toHaveLength(0);
  });
});
