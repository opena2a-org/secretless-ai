import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { spawn } from 'child_process';
import { McpVault } from './vault';

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-mcp-wrapper-'));
}

function cleanup(dir: string): void {
  fs.rmSync(dir, { recursive: true, force: true });
}

/**
 * Run the wrapper via node and capture output.
 * Uses a simple echo script as the "MCP server" to verify env injection.
 */
function runWrapper(args: string[], env: Record<string, string> = {}): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const wrapperPath = path.join(__dirname, '..', '..', 'dist', 'mcp-wrapper.js');
    const proc = spawn('node', [wrapperPath, ...args], {
      env: { ...process.env, ...env },
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';
    proc.stdout.on('data', (d) => { stdout += d.toString(); });
    proc.stderr.on('data', (d) => { stderr += d.toString(); });
    proc.on('close', (code) => resolve({ code: code ?? 1, stdout, stderr }));

    // Close stdin so the child process doesn't hang
    proc.stdin.end();
  });
}

describe('secretless-mcp wrapper', () => {
  let dir: string;

  beforeEach(() => { dir = tmpDir(); });
  afterEach(() => { cleanup(dir); });

  it('injects secrets as env vars into child process', async () => {
    // Store a secret in the vault
    const vault = new McpVault({ storeDir: dir, key: 'test-key', backendType: 'local' });
    await vault.storeServerSecrets('cursor', 'test-server', {
      MY_SECRET: 'injected-value-123',
    });

    // Create a simple script that prints env vars
    const scriptPath = path.join(dir, 'echo-env.js');
    fs.writeFileSync(scriptPath, 'console.log(JSON.stringify({ MY_SECRET: process.env.MY_SECRET }));');

    const result = await runWrapper(
      ['--server', 'test-server', '--client', 'cursor', '--vault-dir', dir, '--vault-key', 'test-key', '--backend', 'local', '--', 'node', scriptPath],
    );

    expect(result.code).toBe(0);
    const output = JSON.parse(result.stdout.trim());
    expect(output.MY_SECRET).toBe('injected-value-123');
  });

  it('exits with error when vault dir is missing', async () => {
    const result = await runWrapper(
      ['--server', 'x', '--client', 'y', '--vault-dir', '/nonexistent/path', '--backend', 'local', '--', 'echo', 'hi'],
    );

    expect(result.code).not.toBe(0);
    expect(result.stderr).toContain('secretless-mcp');
  });

  it('exits with error when no command specified after --', async () => {
    const result = await runWrapper(
      ['--server', 'x', '--client', 'y'],
    );

    expect(result.code).not.toBe(0);
    expect(result.stderr).toContain('Usage');
  });

  it('passes through child exit code', async () => {
    const scriptPath = path.join(dir, 'fail.js');
    fs.writeFileSync(scriptPath, 'process.exit(42);');

    const vault = new McpVault({ storeDir: dir, key: 'test-key', backendType: 'local' });
    await vault.storeServerSecrets('cursor', 'srv', {});

    const result = await runWrapper(
      ['--server', 'srv', '--client', 'cursor', '--vault-dir', dir, '--vault-key', 'test-key', '--backend', 'local', '--', 'node', scriptPath],
    );

    expect(result.code).toBe(42);
  });

  it('passes existing env vars through to child', async () => {
    const vault = new McpVault({ storeDir: dir, key: 'test-key', backendType: 'local' });
    await vault.storeServerSecrets('cursor', 'srv', { INJECTED: 'from-vault' });

    const scriptPath = path.join(dir, 'check-env.js');
    fs.writeFileSync(scriptPath, `
      console.log(JSON.stringify({
        INJECTED: process.env.INJECTED,
        EXISTING: process.env.EXISTING_VAR,
      }));
    `);

    const result = await runWrapper(
      ['--server', 'srv', '--client', 'cursor', '--vault-dir', dir, '--vault-key', 'test-key', '--backend', 'local', '--', 'node', scriptPath],
      { EXISTING_VAR: 'already-here' },
    );

    expect(result.code).toBe(0);
    const output = JSON.parse(result.stdout.trim());
    expect(output.INJECTED).toBe('from-vault');
    expect(output.EXISTING).toBe('already-here');
  });
});
