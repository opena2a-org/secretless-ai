import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runWithSecrets } from './run';
import { LocalBackend } from './backends/local';
import { SecretStore } from './secret-store';

describe('runWithSecrets', () => {
  let tmpDir: string;
  let backend: LocalBackend;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-run-test-'));
    backend = new LocalBackend({ storeDir: tmpDir, key: 'test-key' });
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('injects secrets as env vars into child process', async () => {
    const store = new SecretStore({ backend });
    await store.setSecret('TEST_SECRET', 'hello123');

    // Use node to print the env var
    const code = await runWithSecrets('node', ['-e', `
      const val = process.env.TEST_SECRET;
      if (val !== 'hello123') { process.exit(1); }
    `], { backend });

    expect(code).toBe(0);
  });

  it('injects only specified secrets with --only', async () => {
    const store = new SecretStore({ backend });
    await store.setSecret('KEEP', 'yes');
    await store.setSecret('SKIP', 'no');

    const code = await runWithSecrets('node', ['-e', `
      if (process.env.KEEP !== 'yes') process.exit(1);
      if (process.env.SKIP !== undefined) process.exit(2);
    `], { backend, only: ['KEEP'] });

    expect(code).toBe(0);
  });

  it('forwards child exit code', async () => {
    const code = await runWithSecrets('node', ['-e', 'process.exit(42)'], { backend });
    expect(code).toBe(42);
  });

  it('returns 1 for nonexistent command', async () => {
    const code = await runWithSecrets('nonexistent-command-xyz', [], { backend });
    expect(code).toBe(1);
  });

  it('preserves existing env vars', async () => {
    const store = new SecretStore({ backend });
    await store.setSecret('INJECTED', 'from-store');

    const code = await runWithSecrets('node', ['-e', `
      if (!process.env.HOME) process.exit(1);
      if (process.env.INJECTED !== 'from-store') process.exit(2);
    `], { backend });

    expect(code).toBe(0);
  });
});
