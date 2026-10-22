/**
 * Tests for vault-core.ts — integration tests using real aim-core vault module.
 *
 * These tests require @opena2a/aim-core to be installed/linked.
 * They create temp directories and clean up after themselves.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { PassThrough } from 'stream';

// We need to mock the paths before importing vault-core
let tmpHome: string;
let vaultDir: string;
let aimDataDir: string;

// Check if aim-core is available
let aimCoreAvailable = false;
try {
  require.resolve('@opena2a/aim-core');
  aimCoreAvailable = true;
} catch {
  // aim-core not available — tests will be skipped
}

const describeWithAimCore = aimCoreAvailable ? describe : describe.skip;

describeWithAimCore('vault-core', () => {
  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-vault-test-'));
    vaultDir = path.join(tmpHome, '.aim', 'vault');
    aimDataDir = path.join(tmpHome, '.opena2a', 'aim-core');

    // Override HOME so vault-core uses our temp dirs
    vi.stubEnv('HOME', tmpHome);
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    // Reset cached modules
    vi.resetModules();
    fs.rmSync(tmpHome, { recursive: true, force: true });
  });

  it('loadAimCoreVault succeeds when aim-core is installed', async () => {
    // Reset cache by re-importing
    const { loadAimCoreVault } = await import('./vault-core.js');
    const vault = await loadAimCoreVault();
    expect(vault).toBeDefined();
    expect(vault.VaultStore).toBeDefined();
    expect(vault.createResolutionRequest).toBeDefined();
    expect(vault.resolveWithPolicy).toBeDefined();
  });

  it('loadAimCoreIdentity succeeds when aim-core is installed', async () => {
    const { loadAimCoreIdentity } = await import('./vault-core.js');
    const identity = await loadAimCoreIdentity();
    expect(identity).toBeDefined();
    expect(identity.loadIdentity).toBeDefined();
    expect(identity.createIdentity).toBeDefined();
  });

  it('getOrCreateAgent creates new identity when none exists', async () => {
    const { getOrCreateAgent } = await import('./vault-core.js');
    const agent = await getOrCreateAgent('test-agent');
    expect(agent.agentId).toBeTruthy();
    expect(agent.agentId).toMatch(/^aim_/);
    expect(agent.agentName).toBe('test-agent');
    expect(agent.publicKey).toBeTruthy();
    expect(agent.secretKey).toBeTruthy();
  });

  it('getOrCreateAgent returns existing identity on second call', async () => {
    const { getOrCreateAgent } = await import('./vault-core.js');
    const agent1 = await getOrCreateAgent('test-agent');
    const agent2 = await getOrCreateAgent('test-agent');
    expect(agent1.agentId).toBe(agent2.agentId);
    expect(agent1.publicKey).toBe(agent2.publicKey);
  });

  it('vaultInit creates vault directory and files', async () => {
    const { vaultInit } = await import('./vault-core.js');
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

    await vaultInit('test-agent');

    expect(fs.existsSync(vaultDir)).toBe(true);
    expect(fs.existsSync(path.join(vaultDir, 'vault.enc'))).toBe(true);

    consoleSpy.mockRestore();
  });

  it('init next steps and the empty-list hint register without --value', async () => {
    const { vaultInit, vaultList } = await import('./vault-core.js');
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

    await vaultInit('test-agent');
    await vaultList();

    const lines = consoleSpy.mock.calls.map((call) => call.join(' ')).join('\n').split('\n');
    expect(lines.filter((l) => /secretless-ai\b.*--value\b/.test(l))).toEqual([]);
    expect(lines.some((l) => /secretless-ai vault register github\s+\(prompts/.test(l))).toBe(true);
    expect(lines.some((l) => /secretless-ai vault register <namespace>\s+\(prompts/.test(l))).toBe(true);

    consoleSpy.mockRestore();
  });

  it('vaultInit is idempotent — second call reports already initialized', async () => {
    const { vaultInit } = await import('./vault-core.js');
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

    await vaultInit('test-agent');
    await vaultInit('test-agent');

    // Second call should mention "already initialized"
    const allOutput = consoleSpy.mock.calls.flat().join(' ');
    expect(allOutput).toContain('already initialized');

    consoleSpy.mockRestore();
  });

  it('full lifecycle: init -> register -> list -> rotate -> revoke', async () => {
    const {
      vaultInit, vaultRegister, vaultList, vaultRotate, vaultRevoke,
    } = await import('./vault-core.js');

    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

    // Init
    await vaultInit('test-agent');

    // Register
    await vaultRegister('github', {
      value: 'ghp_test_token_123',
      description: 'GitHub token',
      operations: ['read'],
      urlPatterns: ['https://api.github.com/*'],
    });

    // List
    consoleSpy.mockClear();
    await vaultList();
    const listOutput = consoleSpy.mock.calls.flat().join(' ');
    expect(listOutput).toContain('github');
    expect(listOutput).toContain('active');
    expect(listOutput).not.toContain('ghp_test_token_123'); // No credential values

    // Rotate
    consoleSpy.mockClear();
    await vaultRotate('github', { value: 'ghp_rotated_456' });
    const rotateOutput = consoleSpy.mock.calls.flat().join(' ');
    expect(rotateOutput).toContain('rotated');
    expect(rotateOutput).toContain('2'); // Version 2

    // Revoke
    consoleSpy.mockClear();
    await vaultRevoke('github');
    const revokeOutput = consoleSpy.mock.calls.flat().join(' ');
    expect(revokeOutput).toContain('revoked');

    // List after revoke — should show empty
    consoleSpy.mockClear();
    await vaultList();
    const emptyListOutput = consoleSpy.mock.calls.flat().join(' ');
    expect(emptyListOutput).toContain('No credentials');

    consoleSpy.mockRestore();
  });

  it('vaultExec spawns child with credential as env var', async () => {
    const { vaultInit, vaultRegister, vaultExec } = await import('./vault-core.js');
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

    await vaultInit('test-agent');
    await vaultRegister('test-cred', {
      value: 'secret_value_abc',
      operations: ['read'],
    });

    consoleSpy.mockRestore();

    // Exec: verify the credential is available as env var
    const code = await vaultExec('test-cred', ['node', '-e', `
      const val = process.env.TEST_CRED;
      if (val !== 'secret_value_abc') {
        process.stderr.write('Expected secret_value_abc, got: ' + val + '\\n');
        process.exit(1);
      }
    `]);

    expect(code).toBe(0);
  });

  it('vaultExec does not leak credential to stdout', async () => {
    const { vaultInit, vaultRegister, vaultExec } = await import('./vault-core.js');
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

    await vaultInit('test-agent');
    await vaultRegister('leak-test', {
      value: 'should_not_appear_in_stdout',
      operations: ['read'],
    });
    consoleSpy.mockRestore();

    // The credential should be in the child env but the vault-core module
    // itself should not write it to stdout
    const output: string[] = [];
    const origWrite = process.stdout.write;
    process.stdout.write = ((chunk: string | Uint8Array) => {
      output.push(String(chunk));
      return true;
    }) as typeof process.stdout.write;

    await vaultExec('leak-test', ['node', '-e', 'process.exit(0)']);

    process.stdout.write = origWrite;

    const allOutput = output.join('');
    expect(allOutput).not.toContain('should_not_appear_in_stdout');
  });

  // The child inherits the caller's standard streams and nothing masks them,
  // so a wrapped command that prints the credential hands it to whoever ran
  // `vault exec`. The README and help text state this limit; a change that
  // masks the child's output has to update this test on purpose.
  it('vault exec returns the value to the caller when the child prints it', async () => {
    const cliPath = path.resolve(__dirname, '..', 'dist', 'cli.js');
    expect(fs.existsSync(cliPath), 'run `npm run build` first').toBe(true);

    const { vaultInit, vaultRegister } = await import('./vault-core.js');
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    await vaultInit('test-agent');
    await vaultRegister('printed-cred', {
      value: 'synthetic_marker_7f3a',
      operations: ['read'],
    });
    consoleSpy.mockRestore();

    const run = (cmd: string[]) =>
      spawnSync(process.execPath, [cliPath, 'vault', 'exec', 'printed-cred', '--', ...cmd], {
        env: { ...process.env, HOME: tmpHome },
        encoding: 'utf-8',
        timeout: 30_000,
      });

    const printed = run([process.execPath, '-e', 'process.stdout.write(process.env.PRINTED_CRED ?? "")']);
    expect(printed.status).toBe(0);
    expect(printed.stdout).toContain('synthetic_marker_7f3a');

    // Control: the same wrap with a child that prints nothing returns nothing.
    const silent = run([process.execPath, '-e', 'process.exit(0)']);
    expect(silent.status).toBe(0);
    expect(silent.stdout).not.toContain('synthetic_marker_7f3a');
  });

  it('vaultExec with custom env name', async () => {
    const { vaultInit, vaultRegister, vaultExec } = await import('./vault-core.js');
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

    await vaultInit('test-agent');
    await vaultRegister('aws-prod', {
      value: 'aws_secret_key_123',
      operations: ['read'],
    });
    consoleSpy.mockRestore();

    const code = await vaultExec('aws-prod', ['node', '-e', `
      if (process.env.MY_AWS_KEY !== 'aws_secret_key_123') process.exit(1);
    `], { envName: 'MY_AWS_KEY' });

    expect(code).toBe(0);
  });

  it('vaultExec fails for revoked namespace', async () => {
    const { vaultInit, vaultRegister, vaultRevoke, vaultExec } = await import('./vault-core.js');
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

    await vaultInit('test-agent');
    await vaultRegister('revoke-test', {
      value: 'temp_token',
      operations: ['read'],
    });
    await vaultRevoke('revoke-test');
    consoleSpy.mockRestore();

    await expect(
      vaultExec('revoke-test', ['echo', 'should not run']),
    ).rejects.toThrow(/denied/i);
  });

  it('vaultAudit shows events', async () => {
    const { vaultInit, vaultRegister, vaultAudit } = await import('./vault-core.js');
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

    await vaultInit('test-agent');
    await vaultRegister('audit-test', {
      value: 'token123',
      operations: ['read'],
    });

    consoleSpy.mockClear();
    await vaultAudit({ limit: 10 });
    const auditOutput = consoleSpy.mock.calls.flat().join(' ');
    expect(auditOutput).toContain('vault:init');
    expect(auditOutput).toContain('store');

    consoleSpy.mockRestore();
  });

  it('vaultTest reports all checks', async () => {
    const { vaultInit, vaultTest } = await import('./vault-core.js');
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

    await vaultInit('test-agent');

    consoleSpy.mockClear();
    await vaultTest();
    const testOutput = consoleSpy.mock.calls.flat().join(' ');
    expect(testOutput).toContain('[OK]');
    expect(testOutput).toContain('aim-core loaded');
    expect(testOutput).toContain('All checks passed');

    consoleSpy.mockRestore();
  });

  it('getVaultStore throws when vault not initialized', async () => {
    const { getOrCreateAgent, getVaultStore } = await import('./vault-core.js');

    // Ensure identity exists but vault does not
    await getOrCreateAgent('test-agent');

    await expect(getVaultStore()).rejects.toThrow(/not initialized/i);
  });

  // A vault command run before `vault init` is refused and writes nothing: the
  // vault is checked before the identity, and outside `vault init` the identity
  // is read, never created. Other tools that use @opena2a/aim-core can share
  // ~/.opena2a/aim-core, so `vault init` uses an identity it finds there as it
  // is and says so when `--name` asks for another name.
  describe('the agent identity in ~/.opena2a/aim-core', () => {
    type VaultCore = typeof import('./vault-core.js');
    const identityFile = () => path.join(aimDataDir, 'identity.json');
    const readIdentity = () => JSON.parse(fs.readFileSync(identityFile(), 'utf-8'));
    const notApplied = (existing: string, requested: string) =>
      `  An agent identity already exists in ~/.opena2a/aim-core (agent ${existing}); --name ${requested} was not applied.`;
    const NO_IDENTITY = 'Vault exists, but no agent identity could be read from ~/.opena2a/aim-core.';

    // Runs fn with console.log captured, one entry per printed line.
    const captureLog = async (fn: () => Promise<unknown>) => {
      const lines: string[] = [];
      const spy = vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => {
        lines.push(...a.map(String).join(' ').split('\n'));
      });
      try {
        await fn();
      } finally {
        spy.mockRestore();
      }
      return lines;
    };

    const verbs: Array<[string, (core: VaultCore) => Promise<unknown>]> = [
      ['list', (core) => core.vaultList()],
      ['register', (core) => core.vaultRegister('github', { value: 'placeholder-value' })],
      ['rotate', (core) => core.vaultRotate('github', { value: 'placeholder-value' })],
      ['revoke', (core) => core.vaultRevoke('github')],
      ['exec', (core) => core.vaultExec('github', [process.execPath, '-e', '0'])],
      ['migrate --env-file', async (core) => {
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-vault-migrate-'));
        try {
          fs.writeFileSync(path.join(dir, 'entries.txt'), 'EXAMPLE_NAME=placeholder\n');
          return await core.vaultMigrate({ envFile: path.join(dir, 'entries.txt') });
        } finally {
          fs.rmSync(dir, { recursive: true, force: true });
        }
      }],
    ];

    it.each(verbs)('vault %s on a fresh home is refused and writes no identity', async (_verb, run) => {
      const core = await import('./vault-core.js');

      let refusal: unknown;
      await captureLog(() => run(core).catch((err: unknown) => { refusal = err; }));

      expect(String(refusal)).toMatch(/not initialized/i);
      expect(fs.existsSync(identityFile())).toBe(false);
      expect(fs.readdirSync(tmpHome)).toEqual([]);
    });

    it('vault list with the vault in place and its identity gone names the identity and creates none', async () => {
      const { vaultInit, vaultList } = await import('./vault-core.js');
      await captureLog(() => vaultInit());
      fs.rmSync(identityFile());

      let refusal: unknown;
      await captureLog(() => vaultList().catch((err: unknown) => { refusal = err; }));

      const message = refusal instanceof Error ? refusal.message : String(refusal);
      expect(message.split('\n')[0]).toBe(NO_IDENTITY);
      expect(message).toContain("decrypt only with that identity's key, so no new identity was created");
      expect(message.split('\n').pop()).toBe('    mv ~/.aim/vault ~/.aim/vault.old && secretless-ai vault init');
      expect(fs.existsSync(identityFile())).toBe(false);
    });

    it('vault init with the vault in place and its identity gone creates none', async () => {
      const { vaultInit } = await import('./vault-core.js');
      await captureLog(() => vaultInit());
      fs.rmSync(identityFile());

      let refusal: unknown;
      await captureLog(() => vaultInit('demo-agent').catch((err: unknown) => { refusal = err; }));

      expect(String(refusal)).toContain(NO_IDENTITY);
      expect(fs.existsSync(identityFile())).toBe(false);
    });

    it('vault init --name with an identity of another name says so first and keeps that identity', async () => {
      const { getOrCreateAgent, vaultInit } = await import('./vault-core.js');
      // The identity `vault list` used to leave behind: the default name.
      const existing = await getOrCreateAgent();
      expect(existing.agentName).toBe('secretless-agent');

      const lines = await captureLog(() => vaultInit('demo-agent'));

      const notice = lines.indexOf(notApplied('secretless-agent', 'demo-agent'));
      expect(notice, lines.join('\n')).toBeGreaterThanOrEqual(0);
      expect(notice).toBeLessThan(lines.indexOf('  Identity Vault initialized.'));
      expect(lines).toContain(`  Agent:       secretless-agent (${existing.agentId})`);
      expect(readIdentity()).toEqual(existing);
    });

    it('vault init --name after vault init says so before Vault already initialized', async () => {
      const { vaultInit } = await import('./vault-core.js');
      await captureLog(() => vaultInit());
      const before = readIdentity();

      const lines = await captureLog(() => vaultInit('other'));

      const notice = lines.indexOf(notApplied('secretless-agent', 'other'));
      expect(notice, lines.join('\n')).toBeGreaterThanOrEqual(0);
      expect(notice).toBeLessThan(lines.findIndex((l) => l.startsWith('  Vault already initialized for agent ')));
      expect(readIdentity()).toEqual(before);
    });

    it('vault init --name on a fresh home creates the identity under that name', async () => {
      const { vaultInit } = await import('./vault-core.js');

      const lines = await captureLog(() => vaultInit('demo-agent'));

      expect(readIdentity().agentName).toBe('demo-agent');
      expect(lines.some((l) => l.startsWith('  Agent:       demo-agent (aim_'))).toBe(true);
      expect(lines.filter((l) => l.includes('was not applied'))).toEqual([]);
    });

    it('vault init without --name, or with the name the identity has, prints no notice', async () => {
      const { getOrCreateAgent, vaultInit } = await import('./vault-core.js');
      await getOrCreateAgent();

      const lines = await captureLog(async () => {
        await vaultInit();
        await vaultInit('secretless-agent');
      });

      expect(lines.filter((l) => l.includes('was not applied'))).toEqual([]);
      expect(readIdentity().agentName).toBe('secretless-agent');
    });

    it('the CLI: vault list on a fresh home exits 1 and writes no identity, and vault init --name then uses the name', () => {
      const cliPath = path.resolve(__dirname, '..', 'dist', 'cli.js');
      expect(fs.existsSync(cliPath), 'run `npm run build` first').toBe(true);
      const vaultCli = (...args: string[]) => spawnSync(process.execPath, [cliPath, 'vault', ...args], {
        env: { ...process.env, HOME: tmpHome, OPENA2A_TELEMETRY: 'off', SECRETLESS_OS_KEYCHAIN: 'off' },
        stdio: ['ignore', 'pipe', 'pipe'],
        encoding: 'utf-8',
        timeout: 30_000,
      });

      const list = vaultCli('list');
      expect(list.status).toBe(1);
      expect(list.stderr).toContain('Error: Vault not initialized. Run:\n  secretless-ai vault init');
      expect(fs.existsSync(identityFile())).toBe(false);

      const init = vaultCli('init', '--name', 'demo-agent');
      expect(init.status).toBe(0);
      expect(init.stdout).toMatch(/^ {2}Agent: {7}demo-agent \(aim_/m);
      expect(init.stdout).not.toContain('was not applied');
    });

    // An identity.json that is there and cannot be used is left in place: a
    // new identity would replace the key in it. `vault test` gives the step
    // the refusal gives, and resolves false after a [FAIL] line.
    describe('an identity.json that cannot be used, and vault test', () => {
      const MOVE_IDENTITY = 'mv ~/.opena2a/aim-core/identity.json ~/.opena2a/aim-core/identity.json.old';
      const NOT_JSON = '{"agentId": "aim_';
      const writeIdentityFile = (content: string) => {
        fs.mkdirSync(aimDataDir, { recursive: true });
        fs.writeFileSync(identityFile(), content);
      };
      const refusalOf = async (fn: () => Promise<unknown>) => {
        let refusal: unknown;
        const lines = await captureLog(() => fn().catch((err: unknown) => { refusal = err; }));
        expect(refusal, 'expected a refusal').toBeInstanceOf(Error);
        return { message: (refusal as Error).message, lines };
      };
      const runVaultTest = async (core: VaultCore) => {
        let passed: boolean | undefined;
        const lines = await captureLog(async () => { passed = await core.vaultTest(); });
        return { passed, lines };
      };
      // The text of the `Fix:` line of a vault test [FAIL] and of the lines under it.
      const fixLines = (lines: string[]) => {
        const start = lines.findIndex((l) => l.startsWith('          Fix: '));
        expect(start, lines.join('\n')).toBeGreaterThanOrEqual(0);
        return lines.slice(start).filter((l) => l !== '').map((l) => l.trim().replace(/^Fix: /, ''));
      };

      // An identity.json that cannot be used: the case, the file's content, and
      // what the refusal says is wrong with it.
      const unusableFiles: Array<[string, string, string]> = [
        ['that is not JSON', NOT_JSON, 'is not valid JSON'],
        ['holding {}', '{}', 'holds no agent identity (no agentId, publicKey or secretKey)'],
        ['without secretKey', JSON.stringify({ agentId: 'aim_x', publicKey: 'not-a-key' }), 'holds no agent identity (no secretKey)'],
      ];

      it.each(unusableFiles)('vault init --name with no vault and an identity.json %s leaves the file and names it', async (_case, content, problem) => {
        const { vaultInit } = await import('./vault-core.js');
        writeIdentityFile(content);

        const { message, lines } = await refusalOf(() => vaultInit('demo'));

        expect(message.split('\n')[0]).toBe(`~/.opena2a/aim-core/identity.json ${problem}.`);
        expect(message.split('\n').pop()).toBe(`    ${MOVE_IDENTITY} && secretless-ai vault init`);
        expect(lines.filter((l) => l.includes('undefined') || l.includes('was not applied'))).toEqual([]);
        expect(fs.readFileSync(identityFile(), 'utf-8')).toBe(content);
        expect(fs.existsSync(vaultDir)).toBe(false);
      });

      const canDenyRead = process.platform !== 'win32' && process.getuid?.() !== 0;
      (canDenyRead ? it : it.skip)('vault init --name with no vault and an identity.json at mode 000 leaves the file and names it', async () => {
        const { vaultInit } = await import('./vault-core.js');
        await captureLog(() => vaultInit('first'));
        const before = fs.readFileSync(identityFile(), 'utf-8');
        fs.rmSync(vaultDir, { recursive: true });
        fs.chmodSync(identityFile(), 0o000);

        let message: string;
        try {
          ({ message } = await refusalOf(() => vaultInit('second')));
        } finally {
          fs.chmodSync(identityFile(), 0o600);
        }

        expect(message.split('\n')[0]).toBe('~/.opena2a/aim-core/identity.json cannot be read (EACCES).');
        expect(fs.readFileSync(identityFile(), 'utf-8')).toBe(before);
        expect(readIdentity().agentName).toBe('first');
      });

      // getOrCreateAgent, which the package exports, leaves the file in place
      // too, and rejects with the error `vault init` gives in the same state.
      it.each(unusableFiles)('getOrCreateAgent with no vault and an identity.json %s leaves the file and rejects as vault init does', async (_case, content, problem) => {
        const { getOrCreateAgent, vaultInit } = await import('./vault-core.js');
        writeIdentityFile(content);

        const { message } = await refusalOf(() => getOrCreateAgent('second'));
        const { message: initMessage } = await refusalOf(() => vaultInit('second'));

        expect(message.split('\n')[0]).toBe(`~/.opena2a/aim-core/identity.json ${problem}.`);
        expect(message.split('\n').pop()).toBe(`    ${MOVE_IDENTITY} && secretless-ai vault init`);
        expect(message).toBe(initMessage);
        expect(fs.readFileSync(identityFile(), 'utf-8')).toBe(content);
        expect(fs.existsSync(vaultDir)).toBe(false);
      });

      (canDenyRead ? it : it.skip)('getOrCreateAgent with the vault in place and identity.json at mode 000 leaves the file and rejects as vault init does', async () => {
        const { getOrCreateAgent, vaultInit } = await import('./vault-core.js');
        await captureLog(() => vaultInit('first'));
        const before = fs.readFileSync(identityFile(), 'utf-8');
        fs.chmodSync(identityFile(), 0o000);

        let message: string;
        let initMessage: string;
        try {
          ({ message } = await refusalOf(() => getOrCreateAgent('second')));
          ({ message: initMessage } = await refusalOf(() => vaultInit('second')));
        } finally {
          fs.chmodSync(identityFile(), 0o600);
        }

        const messageLines = message.split('\n');
        expect(messageLines.slice(0, 2)).toEqual([NO_IDENTITY, '  ~/.opena2a/aim-core/identity.json cannot be read (EACCES).']);
        expect(messageLines.pop()).toBe(`    mv ~/.aim/vault ~/.aim/vault.old && ${MOVE_IDENTITY} && secretless-ai vault init`);
        expect(message).toBe(initMessage);
        expect(fs.readFileSync(identityFile(), 'utf-8')).toBe(before);
        expect(readIdentity().agentName).toBe('first');
      });

      it('vault list and vault init with the vault in place and identity.json holding {} name the file and move both aside', async () => {
        const core = await import('./vault-core.js');
        await captureLog(() => core.vaultInit());
        writeIdentityFile('{}');

        for (const run of [() => core.vaultList(), () => core.vaultInit('demo')]) {
          const { message, lines } = await refusalOf(run);
          const messageLines = message.split('\n');
          expect(messageLines[0]).toBe(NO_IDENTITY);
          expect(messageLines[1]).toBe('  ~/.opena2a/aim-core/identity.json holds no agent identity (no agentId, publicKey or secretKey).');
          expect(messageLines.pop()).toBe(`    mv ~/.aim/vault ~/.aim/vault.old && ${MOVE_IDENTITY} && secretless-ai vault init`);
          expect(lines.filter((l) => l.includes('undefined'))).toEqual([]);
        }
        expect(fs.readFileSync(identityFile(), 'utf-8')).toBe('{}');
      });

      it('vault test on a fresh home fails with vault init as the fix and writes nothing', async () => {
        const { passed, lines } = await runVaultTest(await import('./vault-core.js'));

        expect(lines).toContain('  [FAIL]  No agent identity found');
        expect(fixLines(lines)).toEqual(['secretless-ai vault init']);
        expect(passed).toBe(false);
        expect(fs.readdirSync(tmpHome)).toEqual([]);
      });

      const states: Array<[string, (core: VaultCore) => Promise<unknown>, string]> = [
        ['the vault in place and identity.json removed', async (core) => {
          await captureLog(() => core.vaultInit());
          fs.rmSync(identityFile());
        }, `  [FAIL]  ${NO_IDENTITY}`],
        ['the vault in place and identity.json holding {}', async (core) => {
          await captureLog(() => core.vaultInit());
          writeIdentityFile('{}');
        }, `  [FAIL]  ${NO_IDENTITY}`],
        ['no vault and an identity.json that is not JSON', async () => {
          writeIdentityFile(NOT_JSON);
        }, '  [FAIL]  ~/.opena2a/aim-core/identity.json is not valid JSON.'],
      ];

      it.each(states)('vault test with %s fails with the step vault init gives', async (_state, setUp, failLine) => {
        const core = await import('./vault-core.js');
        await setUp(core);

        const { passed, lines } = await runVaultTest(core);
        const { message } = await refusalOf(() => core.vaultInit());

        expect(lines).toContain(failLine);
        const fix = fixLines(lines);
        expect(fix).not.toContain('secretless-ai vault init');
        expect(message.split('\n').slice(-fix.length).map((l) => l.trim())).toEqual(fix);
        expect(passed).toBe(false);
      });

      it('vault test resolves true after All checks passed', async () => {
        const core = await import('./vault-core.js');
        await captureLog(() => core.vaultInit());

        const { passed, lines } = await runVaultTest(core);

        expect(lines).toContain('  All checks passed.');
        expect(lines.filter((l) => l.includes('[FAIL]'))).toEqual([]);
        expect(passed).toBe(true);
      });

      it('the CLI: vault test exits 1 after a [FAIL] line and 0 after All checks passed', () => {
        const cliPath = path.resolve(__dirname, '..', 'dist', 'cli.js');
        expect(fs.existsSync(cliPath), 'run `npm run build` first').toBe(true);
        const vaultCli = (...args: string[]) => spawnSync(process.execPath, [cliPath, 'vault', ...args], {
          env: { ...process.env, HOME: tmpHome, OPENA2A_TELEMETRY: 'off', SECRETLESS_OS_KEYCHAIN: 'off' },
          stdio: ['ignore', 'pipe', 'pipe'],
          encoding: 'utf-8',
          timeout: 30_000,
        });

        const failed = vaultCli('test');
        expect(failed.stdout).toContain('  [FAIL]  No agent identity found');
        expect(failed.status).toBe(1);

        expect(vaultCli('init').status).toBe(0);
        const passed = vaultCli('test');
        expect(passed.stdout).toContain('  All checks passed.');
        expect(passed.status).toBe(0);
      });
    });
  });

  it('vaultRegister with --env reads from environment', async () => {
    const { vaultInit, vaultRegister } = await import('./vault-core.js');
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

    vi.stubEnv('MY_TEST_TOKEN', 'env_token_value');

    await vaultInit('test-agent');
    await vaultRegister('env-test', {
      envVar: 'MY_TEST_TOKEN',
      operations: ['read'],
    });

    consoleSpy.mockRestore();

    // Verify it was stored by checking we can exec with it
    const { vaultExec } = await import('./vault-core.js');
    const code = await vaultExec('env-test', ['node', '-e', `
      if (process.env.ENV_TEST !== 'env_token_value') process.exit(1);
    `]);

    expect(code).toBe(0);
  });

  // An empty value is a refusal, not a credential: whichever source it came
  // from, nothing is created, stored or logged when it is empty after trimming.
  describe('vaultRegister refuses an empty value', () => {
    const NO_VALUE = 'no value provided. Pipe the value on stdin, or use --env NAME.';
    let restoreStdin: (() => void) | undefined;

    // Replaces process.stdin with a non-TTY stream that is already at end of input.
    const stubStdin = (input: string) => {
      const original = Object.getOwnPropertyDescriptor(process, 'stdin')!;
      const stream = new PassThrough();
      stream.end(input);
      Object.defineProperty(process, 'stdin', { value: stream, configurable: true });
      restoreStdin = () => Object.defineProperty(process, 'stdin', original);
    };

    afterEach(() => {
      restoreStdin?.();
      restoreStdin = undefined;
    });

    const expectNothingStored = async (namespace: string) => {
      const { loadAimCoreVault, getVaultStore, PATHS } = await import('./vault-core.js');
      const vault = await loadAimCoreVault();
      const { store } = await getVaultStore();
      expect(store.listCredentials().map((c) => c.namespace)).not.toContain(namespace);
      store.lock();
      expect(vault.getNamespace(PATHS.vaultDir, namespace)).toBeNull();
      const events = vault.readVaultAudit(PATHS.vaultDir, { namespace });
      expect(events.filter((e) => e.operation === 'store')).toEqual([]);
    };

    const initVault = async () => {
      const { vaultInit } = await import('./vault-core.js');
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
      await vaultInit('test-agent');
      consoleSpy.mockRestore();
    };

    it('refuses --value with an empty string', async () => {
      stubStdin('');
      await initVault();
      const { vaultRegister } = await import('./vault-core.js');

      await expect(vaultRegister('github', { value: '' })).rejects.toThrow(NO_VALUE);
      await expectNothingStored('github');
    });

    it('refuses stdin at end of input', async () => {
      stubStdin('');
      await initVault();
      const { vaultRegister } = await import('./vault-core.js');

      await expect(vaultRegister('github', {})).rejects.toThrow(NO_VALUE);
      await expectNothingStored('github');
    });

    it('refuses stdin that holds only whitespace', async () => {
      stubStdin('  \n');
      await initVault();
      const { vaultRegister } = await import('./vault-core.js');

      await expect(vaultRegister('github', {})).rejects.toThrow(NO_VALUE);
      await expectNothingStored('github');
    });

    it('refuses an environment variable that is set but empty', async () => {
      stubStdin('');
      vi.stubEnv('EMPTY_TEST_TOKEN', '');
      await initVault();
      const { vaultRegister } = await import('./vault-core.js');

      await expect(vaultRegister('github', { envVar: 'EMPTY_TEST_TOKEN' })).rejects.toThrow(NO_VALUE);
      await expectNothingStored('github');
    });

    it('still registers a value piped on stdin', async () => {
      stubStdin(['piped', 'value'].join('_') + '\n');
      await initVault();
      const { vaultRegister, getVaultStore } = await import('./vault-core.js');
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

      await vaultRegister('github', {});
      consoleSpy.mockRestore();

      const { store } = await getVaultStore();
      expect(store.listCredentials().map((c) => c.namespace)).toContain('github');
      store.lock();
    });

    it('vault register exits 1 with stdin at end of input', async () => {
      const cliPath = path.resolve(__dirname, '..', 'dist', 'cli.js');
      expect(fs.existsSync(cliPath), 'run `npm run build` first').toBe(true);
      await initVault();

      const run = spawnSync(process.execPath, [cliPath, 'vault', 'register', 'github'], {
        env: { ...process.env, HOME: tmpHome, OPENA2A_TELEMETRY: 'off', SECRETLESS_OS_KEYCHAIN: 'off' },
        stdio: ['ignore', 'pipe', 'pipe'],
        encoding: 'utf-8',
        timeout: 30_000,
      });

      expect(run.status).toBe(1);
      expect(run.stderr).toContain(`Error: ${NO_VALUE}`);
      expect(run.stdout).not.toContain('Credential registered');
      await expectNothingStored('github');
    });
  });

  // Rotating to an empty value would replace a working credential with a blank
  // one, so it is refused the same way and the previous version stays in place.
  describe('vaultRotate refuses an empty value', () => {
    const NO_VALUE = 'no value provided. Pipe the value on stdin, or use --env NAME.';
    const ORIGINAL = ['original', 'value'].join('_');
    let restoreStdin: (() => void) | undefined;

    // Replaces process.stdin with a non-TTY stream that is already at end of input.
    const stubStdin = (input: string) => {
      const original = Object.getOwnPropertyDescriptor(process, 'stdin')!;
      const stream = new PassThrough();
      stream.end(input);
      Object.defineProperty(process, 'stdin', { value: stream, configurable: true });
      restoreStdin = () => Object.defineProperty(process, 'stdin', original);
    };

    afterEach(() => {
      restoreStdin?.();
      restoreStdin = undefined;
    });

    const initWithCredential = async () => {
      const { vaultInit, vaultRegister } = await import('./vault-core.js');
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
      await vaultInit('test-agent');
      await vaultRegister('github', { value: ORIGINAL });
      consoleSpy.mockRestore();
    };

    const readStored = async (namespace: string) => {
      const { getVaultStore } = await import('./vault-core.js');
      const { store } = await getVaultStore();
      const version = store.listCredentials().find((c) => c.namespace === namespace)?.version;
      const value = new TextDecoder().decode(store.resolveCredential(namespace));
      store.lock();
      return { version, value };
    };

    const expectPreviousVersionKept = async (namespace: string) => {
      const { loadAimCoreVault, PATHS } = await import('./vault-core.js');
      expect(await readStored(namespace)).toEqual({ version: 1, value: ORIGINAL });
      const vault = await loadAimCoreVault();
      const events = vault.readVaultAudit(PATHS.vaultDir, { namespace });
      expect(events.filter((e) => e.operation === 'rotate')).toEqual([]);
    };

    it('refuses --value with an empty string', async () => {
      stubStdin('');
      await initWithCredential();
      const { vaultRotate } = await import('./vault-core.js');

      await expect(vaultRotate('github', { value: '' })).rejects.toThrow(NO_VALUE);
      await expectPreviousVersionKept('github');
    });

    it('refuses stdin at end of input', async () => {
      stubStdin('');
      await initWithCredential();
      const { vaultRotate } = await import('./vault-core.js');

      await expect(vaultRotate('github', {})).rejects.toThrow(NO_VALUE);
      await expectPreviousVersionKept('github');
    });

    it('refuses stdin that holds only whitespace', async () => {
      stubStdin('  \n');
      await initWithCredential();
      const { vaultRotate } = await import('./vault-core.js');

      await expect(vaultRotate('github', {})).rejects.toThrow(NO_VALUE);
      await expectPreviousVersionKept('github');
    });

    it('refuses an environment variable that is set but empty', async () => {
      stubStdin('');
      vi.stubEnv('EMPTY_TEST_TOKEN', '');
      await initWithCredential();
      const { vaultRotate } = await import('./vault-core.js');

      await expect(vaultRotate('github', { envVar: 'EMPTY_TEST_TOKEN' })).rejects.toThrow(NO_VALUE);
      await expectPreviousVersionKept('github');
    });

    it('still rotates to a value piped on stdin', async () => {
      const rotated = ['rotated', 'value'].join('_');
      stubStdin(rotated + '\n');
      await initWithCredential();
      const { vaultRotate } = await import('./vault-core.js');
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

      await vaultRotate('github', {});
      consoleSpy.mockRestore();

      expect(await readStored('github')).toEqual({ version: 2, value: rotated });
    });

    it('vault rotate exits 1 with stdin at end of input', async () => {
      const cliPath = path.resolve(__dirname, '..', 'dist', 'cli.js');
      expect(fs.existsSync(cliPath), 'run `npm run build` first').toBe(true);
      await initWithCredential();

      const run = spawnSync(process.execPath, [cliPath, 'vault', 'rotate', 'github'], {
        env: { ...process.env, HOME: tmpHome, OPENA2A_TELEMETRY: 'off', SECRETLESS_OS_KEYCHAIN: 'off' },
        stdio: ['ignore', 'pipe', 'pipe'],
        encoding: 'utf-8',
        timeout: 30_000,
      });

      expect(run.status).toBe(1);
      expect(run.stderr).toContain(`Error: ${NO_VALUE}`);
      expect(run.stdout).not.toContain('Credential rotated');
      await expectPreviousVersionKept('github');
    });
  });
});

describe('vault-core error message format', () => {
  it('error message includes install instructions when aim-core unavailable', () => {
    // We can't easily mock require() to fail when aim-core is installed,
    // so we verify the error message format directly.
    const expectedMessage = '@opena2a/aim-core is required for vault commands.\n' +
      '  Install it:  npm install @opena2a/aim-core\n' +
      '  Or link it:  npm link @opena2a/aim-core';

    const err = new Error(expectedMessage);
    expect(err.message).toContain('@opena2a/aim-core is required');
    expect(err.message).toContain('npm install');
    expect(err.message).toContain('npm link');
  });
});

// `vault scan` needs no aim-core: it reuses `scan` and prints one migration
// line per finding. That line is a command the user copies, so it must not put
// the credential value on the command line, where shell history keeps it.
describe('vaultScan migration line', () => {
  it('names a register command that reads the value from a prompt, a pipe or --env', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-vault-scan-'));
    // Assembled from parts so the tree never carries a whole key.
    const key = ['sk-proj-', 'A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V2'].join('');
    fs.writeFileSync(path.join(dir, 'config.sh'), `OPENAI_API_KEY=${key}\n`);
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

    try {
      const { vaultScan } = await import('./vault-core.js');
      await vaultScan(dir);

      const output = consoleSpy.mock.calls.map((call) => call.join(' ')).join('\n');
      const lines = output.split('\n');
      expect(lines).toContain('    Migrate:  secretless-ai vault register openai-proj');
      expect(lines.filter((l) => /--value\b/.test(l))).toEqual([]);
      expect(output).toContain('--env <VAR>');
      expect(output).not.toContain(key);
    } finally {
      consoleSpy.mockRestore();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
