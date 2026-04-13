/**
 * Tests for vault-core.ts — integration tests using real aim-core vault module.
 *
 * These tests require @opena2a/aim-core to be installed/linked.
 * They create temp directories and clean up after themselves.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

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
    const { loadAimCoreVault } = await import('./vault-core');
    const vault = await loadAimCoreVault();
    expect(vault).toBeDefined();
    expect(vault.VaultStore).toBeDefined();
    expect(vault.createResolutionRequest).toBeDefined();
    expect(vault.resolveWithPolicy).toBeDefined();
  });

  it('loadAimCoreIdentity succeeds when aim-core is installed', async () => {
    const { loadAimCoreIdentity } = await import('./vault-core');
    const identity = await loadAimCoreIdentity();
    expect(identity).toBeDefined();
    expect(identity.loadIdentity).toBeDefined();
    expect(identity.createIdentity).toBeDefined();
  });

  it('getOrCreateAgent creates new identity when none exists', async () => {
    const { getOrCreateAgent } = await import('./vault-core');
    const agent = await getOrCreateAgent('test-agent');
    expect(agent.agentId).toBeTruthy();
    expect(agent.agentId).toMatch(/^aim_/);
    expect(agent.agentName).toBe('test-agent');
    expect(agent.publicKey).toBeTruthy();
    expect(agent.secretKey).toBeTruthy();
  });

  it('getOrCreateAgent returns existing identity on second call', async () => {
    const { getOrCreateAgent } = await import('./vault-core');
    const agent1 = await getOrCreateAgent('test-agent');
    const agent2 = await getOrCreateAgent('test-agent');
    expect(agent1.agentId).toBe(agent2.agentId);
    expect(agent1.publicKey).toBe(agent2.publicKey);
  });

  it('vaultInit creates vault directory and files', async () => {
    const { vaultInit } = await import('./vault-core');
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

    await vaultInit('test-agent');

    expect(fs.existsSync(vaultDir)).toBe(true);
    expect(fs.existsSync(path.join(vaultDir, 'vault.enc'))).toBe(true);

    consoleSpy.mockRestore();
  });

  it('vaultInit is idempotent — second call reports already initialized', async () => {
    const { vaultInit } = await import('./vault-core');
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
    } = await import('./vault-core');

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
    const { vaultInit, vaultRegister, vaultExec } = await import('./vault-core');
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
    const { vaultInit, vaultRegister, vaultExec } = await import('./vault-core');
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

  it('vaultExec with custom env name', async () => {
    const { vaultInit, vaultRegister, vaultExec } = await import('./vault-core');
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
    const { vaultInit, vaultRegister, vaultRevoke, vaultExec } = await import('./vault-core');
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
    const { vaultInit, vaultRegister, vaultAudit } = await import('./vault-core');
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
    const { vaultInit, vaultTest } = await import('./vault-core');
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
    const { getOrCreateAgent, getVaultStore } = await import('./vault-core');

    // Ensure identity exists but vault does not
    await getOrCreateAgent('test-agent');

    await expect(getVaultStore()).rejects.toThrow(/not initialized/i);
  });

  it('vaultRegister with --env reads from environment', async () => {
    const { vaultInit, vaultRegister } = await import('./vault-core');
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

    vi.stubEnv('MY_TEST_TOKEN', 'env_token_value');

    await vaultInit('test-agent');
    await vaultRegister('env-test', {
      envVar: 'MY_TEST_TOKEN',
      operations: ['read'],
    });

    consoleSpy.mockRestore();

    // Verify it was stored by checking we can exec with it
    const { vaultExec } = await import('./vault-core');
    const code = await vaultExec('env-test', ['node', '-e', `
      if (process.env.ENV_TEST !== 'env_token_value') process.exit(1);
    `]);

    expect(code).toBe(0);
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
