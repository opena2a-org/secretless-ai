import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { spawnSync } from 'child_process';
import { Readable } from 'stream';
import { runSetup } from './setup';
import { LocalBackend } from './backends/local';
import { SecretStore } from './secret-store';
import { prepareArgv } from './argv';

/**
 * #330: the documented CI recipes passed secrets as environment variables
 * and ran `setup --check`, which counted only the store and so always failed;
 * the 1Password recipe had no way to name 1Password; and `setup` without a
 * terminal took its answers from a pipe, stored a line as the secret whose
 * prompt was open when it arrived (two lines piped at once stored the first
 * name only), and exited 0 without a summary when the input ended with a
 * prompt unanswered.
 */

const CLI_PATH = path.resolve(__dirname, '..', 'dist', 'cli.js');

describe('runSetup counts names set in the environment (#330)', () => {
  let tmpDir: string;
  let storeDir: string;
  let backend: LocalBackend;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sls-setup-env-'));
    storeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sls-setup-env-store-'));
    backend = new LocalBackend({ storeDir, key: 'test-key' });
    fs.writeFileSync(path.join(tmpDir, '.secretless'), 'STRIPE_KEY\nDATABASE_URL\nSENTRY_DSN  optional\n');
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
    fs.rmSync(storeDir, { recursive: true, force: true });
  });

  it('check mode: a required name set in the environment is present, reported as from environment', async () => {
    const result = await runSetup(tmpDir, {
      backend,
      check: true,
      env: { STRIPE_KEY: 'x', DATABASE_URL: 'y' },
    });
    expect(result.complete).toBe(true);
    expect(result.missing).toBe(0);
    expect(result.existing).toBe(0);
    expect(result.fromEnvironmentNames).toEqual(['STRIPE_KEY', 'DATABASE_URL']);
    expect(result.skipped).toBe(1);
  });

  it('check mode: an empty value is not present, as an unset CI secret arrives empty', async () => {
    const result = await runSetup(tmpDir, {
      backend,
      check: true,
      env: { STRIPE_KEY: '', DATABASE_URL: 'y' },
    });
    expect(result.complete).toBe(false);
    expect(result.missingNames).toEqual(['STRIPE_KEY']);
    expect(result.fromEnvironmentNames).toEqual(['DATABASE_URL']);
  });

  it('check mode: an optional name set in the environment is not counted as not set', async () => {
    const result = await runSetup(tmpDir, {
      backend,
      check: true,
      env: { STRIPE_KEY: 'x', DATABASE_URL: 'y', SENTRY_DSN: 'z' },
    });
    expect(result.skipped).toBe(0);
    expect(result.fromEnvironmentNames).toContain('SENTRY_DSN');
  });

  it('check mode: a stored name is still counted from the store, not the environment', async () => {
    await new SecretStore({ backend }).setSecret('STRIPE_KEY', 'stored');
    const result = await runSetup(tmpDir, {
      backend,
      check: true,
      env: { STRIPE_KEY: 'x', DATABASE_URL: 'y' },
    });
    expect(result.existing).toBe(1);
    expect(result.fromEnvironmentNames).toEqual(['DATABASE_URL']);
    expect(result.complete).toBe(true);
  });

  it('without a terminal: prompts for nothing, stores nothing, and reports the missing names', async () => {
    const write = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    try {
      const result = await runSetup(tmpDir, { backend, interactive: false, env: {} });
      expect(result.promptsSkipped).toBe(true);
      expect(result.complete).toBe(false);
      expect(result.missingNames).toEqual(['STRIPE_KEY', 'DATABASE_URL']);
      expect(result.set).toBe(0);
      expect(write.mock.calls.map(c => String(c[0])).join('')).not.toContain('STRIPE_KEY:');
    } finally {
      write.mockRestore();
    }
    expect(await new SecretStore({ backend }).listSecrets()).toEqual([]);
  });

  it('without a terminal: complete when every required name is in the environment', async () => {
    const result = await runSetup(tmpDir, {
      backend,
      interactive: false,
      env: { STRIPE_KEY: 'x', DATABASE_URL: 'y' },
    });
    expect(result.promptsSkipped).toBe(true);
    expect(result.complete).toBe(true);
  });

  it('interactive: input that ends leaves the unanswered required names missing, not complete', async () => {
    const write = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    try {
      const result = await runSetup(tmpDir, {
        backend,
        interactive: true,
        env: {},
        input: Readable.from(['sk_test_value\n']),
      });
      expect(result.set).toBe(1);
      expect(result.complete).toBe(false);
      expect(result.missingNames).toEqual(['DATABASE_URL']);
      expect(result.skipped).toBe(1);
    } finally {
      write.mockRestore();
    }
    expect(await new SecretStore({ backend }).listSecrets()).toEqual(['STRIPE_KEY']);
  });

  it('interactive: Enter on a name set in the environment uses the environment', async () => {
    const write = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    try {
      const result = await runSetup(tmpDir, {
        backend,
        interactive: true,
        env: { STRIPE_KEY: 'x', DATABASE_URL: 'y' },
        input: Readable.from(['\n\n\n']),
      });
      expect(result.complete).toBe(true);
      expect(result.fromEnvironmentNames).toEqual(['STRIPE_KEY', 'DATABASE_URL']);
      expect(write.mock.calls.map(c => String(c[0])).join('')).toContain('set in the environment, press Enter to use it');
    } finally {
      write.mockRestore();
    }
  });

  it('interactive: names the store before the first prompt (#365)', async () => {
    const write = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    let out: string[] = [];
    try {
      await runSetup(tmpDir, {
        backend,
        interactive: true,
        env: {},
        input: Readable.from(['\n\n\n']),
      });
      out = write.mock.calls.map(c => String(c[0]));
    } finally {
      write.mockRestore();
    }
    const store = out.findIndex(l => l.includes('Store: local'));
    const prompt = out.findIndex(l => l.startsWith('  STRIPE_KEY'));
    expect(store, out.join('')).toBeGreaterThanOrEqual(0);
    expect(prompt, out.join('')).toBeGreaterThan(store);
  });
});

describe('secretless-ai setup, as the CI recipes run it (#330)', () => {
  let root: string;
  let home: string;
  let project: string;
  let bin: string;

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'sls330-'));
    home = path.join(root, 'home');
    project = path.join(root, 'project');
    bin = path.join(root, 'bin');
    for (const d of [home, project, bin]) fs.mkdirSync(d);
    // Stand-ins: no OS keychain and no real 1Password CLI is ever reached.
    for (const tool of ['security', 'secret-tool', 'op']) {
      fs.writeFileSync(path.join(bin, tool), '#!/bin/sh\nexit 1\n', { mode: 0o755 });
    }
    fs.mkdirSync(path.join(home, '.secretless-ai'));
    fs.writeFileSync(path.join(home, '.secretless-ai', 'config.json'), JSON.stringify({ backend: 'local' }));
    fs.writeFileSync(path.join(project, '.secretless'), 'STRIPE_KEY\nDATABASE_URL\n');
  });

  afterEach(() => {
    fs.rmSync(root, { recursive: true, force: true });
  });

  function cli(args: string[], extraEnv: Record<string, string> = {}) {
    return spawnSync(process.execPath, [CLI_PATH, 'setup', ...args], {
      cwd: project,
      encoding: 'utf-8',
      // stdin is not a terminal, as in CI.
      stdio: ['ignore', 'pipe', 'pipe'],
      env: {
        PATH: `${bin}${path.delimiter}${process.env.PATH ?? ''}`,
        HOME: home,
        TMPDIR: os.tmpdir(),
        SECRETLESS_OS_KEYCHAIN: 'off',
        OPENA2A_TELEMETRY: 'off',
        NO_COLOR: '1',
        ...extraEnv,
      },
    });
  }

  it('--check passes when the required secrets are passed as environment variables', () => {
    const res = cli(['--check'], { STRIPE_KEY: 'sk_test_value_330', DATABASE_URL: 'postgres://u@h/db330' });
    expect(res.status, res.stdout + res.stderr).toBe(0);
    expect(res.stdout).toContain('Satisfied: 2 secret(s) (2 from environment)');
    expect(res.stdout).toContain('From environment (not stored):');
    expect(res.stdout).toContain('PASS');
    // Names only: a value from the environment is never printed.
    expect(res.stdout + res.stderr).not.toContain('sk_test_value_330');
    expect(res.stdout + res.stderr).not.toContain('db330');
  });

  it('--check still fails when a secret is passed empty', () => {
    const res = cli(['--check'], { STRIPE_KEY: '', DATABASE_URL: 'y' });
    expect(res.status).toBe(1);
    expect(res.stdout).toContain('Missing:   1 required');
    expect(res.stdout).toContain('- STRIPE_KEY');
  });

  it('setup without a terminal and with missing secrets exits 1, not 0', () => {
    const res = cli([]);
    expect(res.status, res.stdout + res.stderr).toBe(1);
    expect(res.stdout).toContain('Standard input is not a terminal');
    expect(res.stdout).toContain('- STRIPE_KEY');
    expect(res.stderr).not.toContain('STRIPE_KEY:');
  });

  it('setup without a terminal exits 0 when the environment provides every required secret', () => {
    const res = cli([], { STRIPE_KEY: 'x', DATABASE_URL: 'y' });
    expect(res.status, res.stdout + res.stderr).toBe(0);
    expect(res.stdout).toContain('PASS');
  });

  it.each([[['--backend', 'local']], [['--backend=local']]])('--check %j names the store it checked', (flags) => {
    const res = cli(['--check', ...flags], { STRIPE_KEY: 'x', DATABASE_URL: 'y' });
    expect(res.status, res.stdout + res.stderr).toBe(0);
    expect(res.stdout).toContain('Store:     local');
  });

  it('--check --backend 1password checks 1Password, not the configured store', () => {
    const res = cli(['--check', '--backend', '1password'], { STRIPE_KEY: 'x', DATABASE_URL: 'y' });
    // The stand-in `op` exits 1, so the 1Password backend is unavailable and
    // says so. Reaching that refusal is the proof the flag selected it.
    expect(res.status).toBe(1);
    expect(res.stdout + res.stderr).toMatch(/1password/i);
    expect(res.stdout).not.toContain('Store:     local');
    expect(res.stdout).not.toContain('PASS');
  });

  it('--check --backend local checks the encrypted file when no backend is configured (#365)', () => {
    // With no config, `local` is the default and upgrades to a platform
    // keychain (always assumed on macOS; the `secret-tool` stand-in makes one
    // likely on Linux). Named with --backend, it is the file.
    fs.rmSync(path.join(home, '.secretless-ai', 'config.json'));
    const res = cli(['--check', '--backend', 'local'], { STRIPE_KEY: 'x', DATABASE_URL: 'y' });
    expect(res.status, res.stdout + res.stderr).toBe(0);
    expect(res.stdout).toContain('Store:     local');
    expect(res.stdout + res.stderr).not.toContain('keychain');
  });

  it('an unreachable --backend is reported as named for this run, with no migration offered (#365)', () => {
    const res = cli(['--check', '--backend', '1password'], { STRIPE_KEY: 'x', DATABASE_URL: 'y' });
    const out = res.stdout + res.stderr;
    expect(res.status).toBe(1);
    expect(out).toContain('Backend "1password", named with --backend, is not reachable');
    expect(out).not.toContain('Configured backend');
    expect(out).not.toContain('backend migrate');
    expect(out).toContain('without --backend');
  });

  it('an unknown --backend is refused before anything runs', () => {
    const res = cli(['--backend', 'bogus']);
    expect(res.status).toBe(2);
    expect(res.stderr).toContain('Unknown backend type: bogus');
    expect(res.stderr).toContain('Nothing was changed');
    expect(res.stdout).not.toContain('Secretless Setup');
  });

  it('the argv registry binds --backend for setup', () => {
    expect(prepareArgv('setup', ['--check', '--backend=1password']).errors).toEqual([]);
    expect(prepareArgv('setup', ['--check', '--backend=1password']).args).toEqual(['--check', '--backend', '1password']);
  });
});
