/**
 * Tests for commands/vault.ts — CLI arg parsing and dispatch.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// Mock all vault-core functions so we can test CLI dispatch without aim-core
vi.mock('../vault-core', () => ({
  vaultInit: vi.fn().mockResolvedValue(undefined),
  vaultRegister: vi.fn().mockResolvedValue(undefined),
  vaultList: vi.fn().mockResolvedValue(undefined),
  vaultRotate: vi.fn().mockResolvedValue(undefined),
  vaultRevoke: vi.fn().mockResolvedValue(undefined),
  vaultAudit: vi.fn().mockResolvedValue(undefined),
  vaultScan: vi.fn().mockResolvedValue(undefined),
  vaultExec: vi.fn().mockResolvedValue(0),
  vaultTest: vi.fn().mockResolvedValue(undefined),
  vaultMigrate: vi.fn().mockResolvedValue(undefined),
}));

import { runVault } from './vault';
import {
  vaultInit,
  vaultRegister,
  vaultList,
  vaultRotate,
  vaultRevoke,
  vaultAudit,
  vaultScan,
  vaultExec,
  vaultTest,
  vaultMigrate,
} from '../vault-core';

describe('runVault CLI dispatch', () => {
  let exitSpy: ReturnType<typeof vi.spyOn>;
  let consoleSpy: ReturnType<typeof vi.spyOn>;
  let consoleErrorSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.clearAllMocks();
    exitSpy = vi.spyOn(process, 'exit').mockImplementation((() => {}) as never);
    consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    exitSpy.mockRestore();
    consoleSpy.mockRestore();
    consoleErrorSpy.mockRestore();
  });

  it('dispatches "init" to vaultInit', () => {
    runVault(['init']);
    expect(vaultInit).toHaveBeenCalledWith(undefined);
  });

  it('dispatches "init --name my-agent" with agent name', () => {
    runVault(['init', '--name', 'my-agent']);
    expect(vaultInit).toHaveBeenCalledWith('my-agent');
  });

  it('dispatches "register" with namespace and options', () => {
    runVault(['register', 'github', '--value', 'ghp_abc', '--description', 'GitHub token']);
    expect(vaultRegister).toHaveBeenCalledWith('github', {
      value: 'ghp_abc',
      envVar: undefined,
      description: 'GitHub token',
      operations: undefined,
      urlPatterns: undefined,
    });
  });

  it('dispatches "register" with --operations and --url-patterns', () => {
    runVault(['register', 'aws', '--env', 'AWS_KEY', '--operations', 'read,write', '--url-patterns', 'https://s3.amazonaws.com/*']);
    expect(vaultRegister).toHaveBeenCalledWith('aws', {
      value: undefined,
      envVar: 'AWS_KEY',
      description: undefined,
      operations: ['read', 'write'],
      urlPatterns: ['https://s3.amazonaws.com/*'],
    });
  });

  it('dispatches "register" without namespace shows usage and exits', async () => {
    expect(await runVault(['register'])).toBe(1);
    expect(vaultRegister).not.toHaveBeenCalled();
  });

  it('dispatches "list" to vaultList', () => {
    runVault(['list']);
    expect(vaultList).toHaveBeenCalled();
  });

  it('dispatches "ls" as alias for list', () => {
    runVault(['ls']);
    expect(vaultList).toHaveBeenCalled();
  });

  it('dispatches "rotate" with namespace and --value', () => {
    runVault(['rotate', 'github', '--value', 'ghp_new']);
    expect(vaultRotate).toHaveBeenCalledWith('github', {
      value: 'ghp_new',
      envVar: undefined,
    });
  });

  it('dispatches "rotate" without namespace shows usage and exits', async () => {
    expect(await runVault(['rotate'])).toBe(1);
    expect(vaultRotate).not.toHaveBeenCalled();
  });

  it('dispatches "revoke" with namespace', () => {
    runVault(['revoke', 'github']);
    expect(vaultRevoke).toHaveBeenCalledWith('github');
  });

  it('dispatches "revoke" without namespace shows usage and exits', async () => {
    expect(await runVault(['revoke'])).toBe(1);
    expect(vaultRevoke).not.toHaveBeenCalled();
  });

  it('dispatches "audit" with options', () => {
    runVault(['audit', '--limit', '20', '--namespace', 'github']);
    expect(vaultAudit).toHaveBeenCalledWith({
      limit: 20,
      since: undefined,
      namespace: 'github',
    });
  });

  it('dispatches "scan" with optional directory', () => {
    runVault(['scan', '/tmp/myproject']);
    expect(vaultScan).toHaveBeenCalledWith('/tmp/myproject');
  });

  it('dispatches "exec" with namespace and command', () => {
    runVault(['exec', 'github', '--', 'curl', 'https://api.github.com/user']);
    expect(vaultExec).toHaveBeenCalledWith(
      'github',
      ['curl', 'https://api.github.com/user'],
      { envName: undefined },
    );
  });

  it('dispatches "exec" with --env-name', () => {
    runVault(['exec', 'aws-prod', '--env-name', 'AWS_SECRET_ACCESS_KEY', '--', 'aws', 's3', 'ls']);
    expect(vaultExec).toHaveBeenCalledWith(
      'aws-prod',
      ['aws', 's3', 'ls'],
      { envName: 'AWS_SECRET_ACCESS_KEY' },
    );
  });

  it('dispatches "exec" without -- shows usage and exits', async () => {
    expect(await runVault(['exec', 'github', 'curl'])).toBe(1);
    expect(vaultExec).not.toHaveBeenCalled();
  });

  it('dispatches "test" to vaultTest', () => {
    runVault(['test']);
    expect(vaultTest).toHaveBeenCalled();
  });

  it('dispatches "migrate" with options', () => {
    runVault(['migrate', '--env-file', '.env', '--dry-run']);
    expect(vaultMigrate).toHaveBeenCalledWith({
      dryRun: true,
      envFile: '.env',
    });
  });

  it('shows help for --help', () => {
    runVault(['--help']);
    const output = consoleSpy.mock.calls.flat().join(' ');
    expect(output).toContain('Identity Vault');
    expect(output).toContain('vault exec');
  });

  it('shows error and help for unknown subcommand', async () => {
    expect(await runVault(['unknown-cmd'])).toBe(1);
    const errorOutput = consoleErrorSpy.mock.calls.flat().join(' ');
    expect(errorOutput).toContain('Unknown vault command: unknown-cmd');
  });

  it('shows help when no subcommand given', () => {
    runVault([]);
    const output = consoleSpy.mock.calls.flat().join(' ');
    expect(output).toContain('Identity Vault');
  });
});
