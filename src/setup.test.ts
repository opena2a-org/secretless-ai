import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runSetup } from './setup';
import { LocalBackend } from './backends/local';
import { SecretStore } from './secret-store';

describe('runSetup', () => {
  let tmpDir: string;
  let storeDir: string;
  let backend: LocalBackend;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-setup-test-'));
    storeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-setup-store-'));
    backend = new LocalBackend({ storeDir, key: 'test-key' });
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
    fs.rmSync(storeDir, { recursive: true, force: true });
  });

  it('reports no manifest found', async () => {
    const result = await runSetup(tmpDir, { backend });
    expect(result.complete).toBe(true);
    expect(result.set).toBe(0);
  });

  it('check mode returns complete when all secrets satisfied', async () => {
    fs.writeFileSync(path.join(tmpDir, '.secretless'), 'API_KEY\n');
    const store = new SecretStore({ backend });
    await store.setSecret('API_KEY', 'value');

    const result = await runSetup(tmpDir, { backend, check: true });
    expect(result.complete).toBe(true);
    expect(result.existing).toBe(1);
  });

  it('check mode returns incomplete when required secrets missing', async () => {
    fs.writeFileSync(path.join(tmpDir, '.secretless'), 'MISSING_KEY\n');

    const result = await runSetup(tmpDir, { backend, check: true });
    expect(result.complete).toBe(false);
    expect(result.existing).toBe(0);
  });

  it('check mode counts optional secrets as skipped', async () => {
    fs.writeFileSync(
      path.join(tmpDir, '.secretless'),
      'REQUIRED\nOPTIONAL_KEY  optional\n',
    );

    const result = await runSetup(tmpDir, { backend, check: true });
    expect(result.complete).toBe(false);
    expect(result.skipped).toBe(1);
  });

  it('returns all existing when nothing is missing', async () => {
    fs.writeFileSync(path.join(tmpDir, '.secretless'), 'A\nB\n');
    const store = new SecretStore({ backend });
    await store.setSecret('A', '1');
    await store.setSecret('B', '2');

    const result = await runSetup(tmpDir, { backend, check: true });
    expect(result.complete).toBe(true);
    expect(result.existing).toBe(2);
  });
});
