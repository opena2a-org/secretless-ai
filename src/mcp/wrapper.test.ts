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
    await vault.storeServerSecrets('cursor', 'srv', { SRV_TOKEN: 'srv-value' });

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

  // #138 item 1: the bin can say which build it is.
  it.each(['--version', '-v'])('%s prints the package version on stdout and exits 0', async (flag) => {
    const result = await runWrapper([flag]);
    const version = JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'package.json'), 'utf-8')).version;

    expect(result.code).toBe(0);
    expect(result.stdout.trim()).toBe(`secretless-mcp ${version}`);
    expect(result.stderr).toBe('');
  });

  // #138 item 2: a pair that matches nothing in the vault refuses instead of
  // starting the server with none of its credentials.
  it('refuses to start the server when the client/server pair has no stored secrets', async () => {
    const vault = new McpVault({ storeDir: dir, key: 'test-key', backendType: 'local' });
    await vault.storeServerSecrets('cursor', 'github', { GITHUB_TOKEN: 'stored-secret-value' });
    await vault.storeServerSecrets('claude-code', 'linear', { LINEAR_KEY: 'another-secret-value' });
    const marker = path.join(dir, 'started');
    const scriptPath = path.join(dir, 'server.js');
    fs.writeFileSync(scriptPath, `require('fs').writeFileSync(${JSON.stringify(marker)}, 'x');`);

    const result = await runWrapper(
      ['--server', 'myserver', '--client', 'bogus-client', '--vault-dir', dir, '--vault-key', 'test-key', '--backend', 'local', '--', 'node', scriptPath],
    );

    expect(result.code).toBe(1);
    expect(fs.existsSync(marker)).toBe(false);
    expect(result.stderr).toContain('No secrets are stored for client "bogus-client", server "myserver" in the local backend. The server was not started.');
    expect(result.stderr).toContain('Stored client/server pairs: claude-code/linear, cursor/github');
    expect(result.stderr).toContain('npx secretless-ai mcp-status');
    // Names only: no stored value reaches either stream.
    expect(result.stdout + result.stderr).not.toContain('secret-value');
  });

  it('says the backend holds no MCP secrets when the vault is empty', async () => {
    const result = await runWrapper(
      ['--server', 'myserver', '--client', 'cursor', '--vault-dir', dir, '--vault-key', 'test-key', '--backend', 'local', '--', 'echo', 'hi'],
    );

    expect(result.code).toBe(1);
    expect(result.stdout).toBe('');
    expect(result.stderr).toContain('The local backend holds no MCP server secrets.');
  });

  // Adjacent: arguments after `--` belong to the MCP server. `-h` is a common
  // host flag; read by the wrapper it printed usage and exited 0 unstarted.
  it.each(['-h', '--help', '--version', '-v'])('passes %s after -- through to the server', async (flag) => {
    const vault = new McpVault({ storeDir: dir, key: 'test-key', backendType: 'local' });
    await vault.storeServerSecrets('cursor', 'srv', { SRV_TOKEN: 'srv-value' });
    const scriptPath = path.join(dir, 'argv.js');
    fs.writeFileSync(scriptPath, 'console.log(JSON.stringify(process.argv.slice(2)));');

    const result = await runWrapper(
      ['--server', 'srv', '--client', 'cursor', '--vault-dir', dir, '--vault-key', 'test-key', '--backend', 'local', '--', 'node', scriptPath, flag, 'localhost'],
    );

    expect(result.code).toBe(0);
    expect(JSON.parse(result.stdout.trim())).toEqual([flag, 'localhost']);
  });
});
