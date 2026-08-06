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

describe('runWithSecrets --only (issue #110) — must not run short or empty', () => {
  let tmpDir2: string;
  let backend2: LocalBackend;
  let marker: string;

  beforeEach(() => {
    tmpDir2 = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-only-test-'));
    backend2 = new LocalBackend({ storeDir: tmpDir2, key: 'test-key' });
    marker = path.join(tmpDir2, 'child-ran.marker');
  });

  afterEach(() => {
    fs.rmSync(tmpDir2, { recursive: true, force: true });
  });

  it('does NOT execute the command when a requested name is missing', async () => {
    const store = new SecretStore({ backend: backend2 });
    await store.setSecret('PRESENT', 'yes');

    await expect(runWithSecrets(
      'node', ['-e', `require('fs').writeFileSync(${JSON.stringify(marker)}, 'ran')`],
      { backend: backend2, only: ['PRESENT', 'ABSENT_NAME'] },
    )).rejects.toThrow(/ABSENT_NAME/);

    expect(fs.existsSync(marker), 'child ran despite a missing credential').toBe(false);
  });

  it('does NOT execute the command on an empty store with --only', async () => {
    // The fail-open path that needs no typo: a CI runner whose store was never
    // populated ran the deploy with no token and reported success.
    await expect(runWithSecrets(
      'node', ['-e', `require('fs').writeFileSync(${JSON.stringify(marker)}, 'ran')`],
      { backend: backend2, only: ['DEPLOY_TOKEN'] },
    )).rejects.toThrow(/DEPLOY_TOKEN/);

    expect(fs.existsSync(marker), 'child ran with nothing injected').toBe(false);
  });

  it('an empty --only list (`--only ,,`) also refuses to run', async () => {
    await expect(runWithSecrets(
      'node', ['-e', `require('fs').writeFileSync(${JSON.stringify(marker)}, 'ran')`],
      { backend: backend2, only: [] },
    )).rejects.toThrow(/named no secrets/);

    expect(fs.existsSync(marker)).toBe(false);
  });

  it('CONTROL: a fully matched --only still runs and injects', async () => {
    const store = new SecretStore({ backend: backend2 });
    await store.setSecret('PRESENT', 'yes');

    const code = await runWithSecrets(
      'node', ['-e', 'process.exit(process.env.PRESENT === "yes" ? 0 : 3)'],
      { backend: backend2, only: ['PRESENT'] },
    );
    expect(code).toBe(0);
  });
});
