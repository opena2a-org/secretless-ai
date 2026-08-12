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

/**
 * #117 — `run` printed a secret value to stderr. Node rejects an environment
 * value containing a null byte and puts the value in the message; the throw is
 * synchronous, so `child.on('error')` never saw it and it went out unredacted.
 * stderr is what CI logs capture.
 *
 * Every assertion here is on the string AS SENT to stderr. Asserting on the
 * error object would test a different string than the one that leaks.
 */
describe('run never writes a secret value to stderr (#117)', () => {
  let tmpDir: string;
  let backend: LocalBackend;
  let written: string;
  let restore: (() => void) | null = null;

  const NUL = String.fromCharCode(0);
  // High-entropy and dictionary-free, so a 4-character run of it appearing in
  // the output means the value leaked, not that English happened.
  const SECRET = 'sk-live-QQ7ZX9WKPV4RJT2MHB6NDY8FGC3L' + NUL + 'ZZTAIL';

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-run-117-'));
    backend = new LocalBackend({ storeDir: tmpDir, key: 'test-key' });
    written = '';
    const original = process.stderr.write.bind(process.stderr);
    (process.stderr as unknown as { write: unknown }).write = (chunk: unknown, ...rest: unknown[]) => {
      written += String(chunk);
      return (original as (...a: unknown[]) => boolean)(chunk, ...rest);
    };
    restore = () => { (process.stderr as unknown as { write: unknown }).write = original; };
  });

  afterEach(() => {
    if (restore) restore();
    restore = null;
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  /** Any run of the value long enough to identify it, in any escaping. */
  function exposesSecret(text: string): boolean {
    if (text.includes(SECRET)) return true;
    for (let i = 0; i + 4 <= SECRET.length; i++) {
      if (text.includes(SECRET.slice(i, i + 4))) return true;
    }
    return false;
  }

  /**
   * Everything this command puts on stderr — including a throw that escapes
   * `run`, because `cli.ts` prints `err.message` to stderr and that is the
   * shape the defect took. Folding it in is what makes these tests fail on
   * their own assertion rather than on an unhandled rejection, which would
   * report a crash and never check what leaked.
   */
  async function stderrOf(
    cmd: string, cmdArgs: string[],
  ): Promise<{ code: number | null; stderr: string }> {
    try {
      const code = await runWithSecrets(cmd, cmdArgs, { backend });
      return { code, stderr: written };
    } catch (err) {
      return { code: null, stderr: written + (err instanceof Error ? err.message : String(err)) };
    }
  }

  it('refuses to run and prints no part of the value', async () => {
    // Written straight to the backend, not via setSecret, because setSecret now
    // refuses this value (#104). That is the realistic path anyway: a
    // null-bearing value reaches the store from a backend read — macOS returns
    // binary passwords hex-encoded and they decode to bytes containing 0x00 —
    // or from a store an older build wrote.
    await backend.store('secret/HIBP_PRO', SECRET);

    const marker = path.join(tmpDir, 'child-ran');
    const { code, stderr } = await stderrOf(
      'node', ['-e', `require('fs').writeFileSync(${JSON.stringify(marker)}, 'ran')`],
    );

    expect(exposesSecret(stderr)).toBe(false);
    // Not merely absent — the escaped form Node would have printed is absent too.
    expect(stderr).not.toContain('\\x00');
    expect(stderr).not.toContain('QQ7ZX9');

    expect(code).toBe(1);
    // Fail closed: a command that runs a credential short surfaces later as an
    // auth error that never mentions secretless.
    expect(fs.existsSync(marker)).toBe(false);

    // And it still tells the user what to do about it.
    expect(stderr).toContain('HIBP_PRO');
    expect(stderr).toContain('secretless-ai secret set HIBP_PRO');
  });

  it('names every unusable secret, not just the first one Node reaches', async () => {
    await backend.store('secret/ALPHA', 'aa' + NUL);
    await backend.store('secret/BETA', 'bb' + NUL);
    await backend.store('secret/FINE', 'ordinary-value');

    const { code, stderr } = await stderrOf('node', ['-e', 'process.exit(0)']);
    expect(stderr).toContain('ALPHA');
    expect(stderr).toContain('BETA');
    expect(code).toBe(1);
  });

  it('CONTROL: an ordinary secret still runs and is injected', async () => {
    // Without this, refusing every run would satisfy the tests above.
    const store = new SecretStore({ backend });
    await store.setSecret('OK_SECRET', 'sk-live-QQ7ZX9WKPV4RJT2MHB6NDY8FGC3L');

    const code = await runWithSecrets(
      'node', ['-e', 'process.exit(process.env.OK_SECRET === "sk-live-QQ7ZX9WKPV4RJT2MHB6NDY8FGC3L" ? 0 : 3)'],
      { backend },
    );
    expect(code).toBe(0);
    expect(written).toBe('');
  });

  it('withholds a spawn failure that carries the value rather than trimming it', async () => {
    // The catch-all, exercised on a value Node accepts so the pre-check does not
    // fire: what has to hold is that the detail is dropped whole, never
    // half-scrubbed. A residue is a leak.
    const store = new SecretStore({ backend });
    const value = 'sk-live-QQ7ZX9WKPV4RJT2MHB6NDY8FGC3L';
    await store.setSecret('TOKEN', value);

    const code = await runWithSecrets(
      `no-such-command-${value}`, [], { backend },
    );
    expect(code).toBe(1);
    expect(written).not.toContain(value);
    expect(written).not.toContain('QQ7ZX9');
  });
});
