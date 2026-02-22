import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { spawn } from 'child_process';
import { protectMcp } from './protect';
import { McpVault } from './vault';
import { installWrapper } from './install-wrapper';

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-mcp-e2e-'));
}

function cleanup(dir: string): void {
  fs.rmSync(dir, { recursive: true, force: true });
}

describe('MCP Protection E2E', () => {
  let homeDir: string;
  let dataDir: string;

  beforeEach(() => {
    homeDir = tmpDir();
    dataDir = tmpDir();
  });
  afterEach(() => {
    cleanup(homeDir);
    cleanup(dataDir);
  });

  it('full flow: protect config -> wrapper injects secrets -> MCP server sees them', async () => {
    // 1. Create a mock Cursor MCP config with a plaintext secret
    const cursorDir = path.join(homeDir, '.cursor');
    fs.mkdirSync(cursorDir, { recursive: true });

    // Create a simple "MCP server" that prints its env
    const mcpServer = path.join(dataDir, 'mock-mcp-server.js');
    fs.writeFileSync(mcpServer, `
      const output = {
        GITHUB_TOKEN: process.env.GITHUB_TOKEN ?? 'NOT_SET',
        GITHUB_ORG: process.env.GITHUB_ORG ?? 'NOT_SET',
      };
      process.stdout.write(JSON.stringify(output));
    `);

    fs.writeFileSync(
      path.join(cursorDir, 'mcp.json'),
      JSON.stringify({
        mcpServers: {
          github: {
            command: 'node',
            args: [mcpServer],
            env: {
              GITHUB_TOKEN: 'ghp_test1234567890abcdef1234567890abcdef1234',
              GITHUB_ORG: 'my-org',
            },
          },
        },
      }, null, 2)
    );

    // 2. Install wrapper to stable location
    const wrapper = installWrapper(dataDir);

    // 3. Run protect-mcp (explicitly local backend so test doesn't depend on config state)
    const result = await protectMcp({
      homeDir,
      dataDir,
      wrapperPath: wrapper.args[0], // path to mcp-wrapper.js
      backendType: 'local',
    });

    expect(result.secretsFound).toBe(1);
    expect(result.serversProtected).toBe(1);

    // 4. Verify config was rewritten
    const config = JSON.parse(fs.readFileSync(path.join(cursorDir, 'mcp.json'), 'utf-8'));
    const github = config.mcpServers.github;
    expect(github.env).not.toHaveProperty('GITHUB_TOKEN');
    expect(github.env.GITHUB_ORG).toBe('my-org');

    // 5. Verify secrets are in the vault
    const vaultDir = path.join(dataDir, 'mcp-vault');
    const vaultKey = `${homeDir}-secretless-mcp-${process.env.USER ?? 'default'}`;
    const vault = new McpVault({ storeDir: vaultDir, key: vaultKey, backendType: 'local' });
    const secrets = await vault.getServerSecrets('cursor', 'github');
    expect(secrets.GITHUB_TOKEN).toBe('ghp_test1234567890abcdef1234567890abcdef1234');

    // 6. Run the wrapper to verify secret injection
    // Simulate what Claude Code / Cursor would do: spawn the command with the args
    const wrapperResult = await new Promise<{ code: number; stdout: string; stderr: string }>((resolve) => {
      const args = github.args as string[];

      // The wrapper needs --vault-dir and --vault-key since it's not using default paths
      // The rewritten config has: args: ['--server', 'github', '--client', 'cursor', '--', 'node', mcpServer]
      // We need to inject vault-dir and vault-key for the test
      const wrapperArgs = [
        wrapper.args[0], // path to mcp-wrapper.js
        '--vault-dir', vaultDir,
        '--vault-key', vaultKey,
        ...args, // --server, github, --client, cursor, --, node, mcpServer
      ];

      const proc = spawn(process.execPath, wrapperArgs, {
        env: { ...process.env, ...github.env },
        stdio: ['pipe', 'pipe', 'pipe'],
      });

      let stdout = '';
      let stderr = '';
      proc.stdout.on('data', (d: Buffer) => { stdout += d.toString(); });
      proc.stderr.on('data', (d: Buffer) => { stderr += d.toString(); });
      proc.on('close', (code) => resolve({ code: code ?? 1, stdout, stderr }));
      proc.stdin.end();
    });

    expect(wrapperResult.code).toBe(0);
    const output = JSON.parse(wrapperResult.stdout.trim());

    // The wrapper should have injected the secret
    expect(output.GITHUB_TOKEN).toBe('ghp_test1234567890abcdef1234567890abcdef1234');
    // Non-secret env var should also be present (passed through config env)
    expect(output.GITHUB_ORG).toBe('my-org');
  });

  it('protect -> unprotect round-trip restores original config', async () => {
    const cursorDir = path.join(homeDir, '.cursor');
    fs.mkdirSync(cursorDir, { recursive: true });

    const originalConfig = {
      mcpServers: {
        jira: {
          command: 'npx',
          args: ['@atlassian/mcp-server-jira'],
          env: {
            JIRA_API_TOKEN: 'ATATT3xFfGF0abc123def456',
            JIRA_EMAIL: 'user@company.com',
            JIRA_URL: 'https://company.atlassian.net',
          },
        },
      },
    };

    const configPath = path.join(cursorDir, 'mcp.json');
    fs.writeFileSync(configPath, JSON.stringify(originalConfig, null, 2));

    const wrapper = installWrapper(dataDir);

    // Protect (explicitly local backend)
    await protectMcp({
      homeDir,
      dataDir,
      wrapperPath: wrapper.args[0],
      backendType: 'local',
    });

    // Verify it's rewritten
    const rewritten = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    expect(rewritten.mcpServers.jira.env).not.toHaveProperty('JIRA_API_TOKEN');

    // Unprotect (restore)
    const { restoreConfig } = await import('./rewrite');
    const backupDir = path.join(dataDir, 'mcp-backups');
    const restored = restoreConfig(configPath, backupDir);
    expect(restored).toBe(true);

    // Verify original is back
    const restoredConfig = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    expect(restoredConfig.mcpServers.jira.env.JIRA_API_TOKEN).toBe('ATATT3xFfGF0abc123def456');
    expect(restoredConfig.mcpServers.jira.env.JIRA_EMAIL).toBe('user@company.com');
    expect(restoredConfig.mcpServers.jira.env.JIRA_URL).toBe('https://company.atlassian.net');
    expect(restoredConfig.mcpServers.jira.command).toBe('npx');
  });

  it('multiple clients with mixed secrets and no-secrets', async () => {
    // Cursor: has secrets
    const cursorDir = path.join(homeDir, '.cursor');
    fs.mkdirSync(cursorDir, { recursive: true });
    fs.writeFileSync(
      path.join(cursorDir, 'mcp.json'),
      JSON.stringify({
        mcpServers: {
          github: { command: 'npx', args: ['gh-mcp'], env: { GITHUB_TOKEN: 'ghp_abc123def456ghi789jkl012mno345pqr678' } },
          filesystem: { command: 'npx', args: ['fs-mcp'], env: { ROOT_DIR: '/home/user' } },
        },
      })
    );

    // Claude Code: has secrets
    const claudeDir = path.join(homeDir, '.claude');
    fs.mkdirSync(claudeDir, { recursive: true });
    fs.writeFileSync(
      path.join(claudeDir, 'settings.json'),
      JSON.stringify({
        mcpServers: {
          db: { command: 'npx', args: ['pg-mcp'], env: { DATABASE_URL: 'postgres://user:secret@host:5432/db' } },
        },
      })
    );

    const wrapper = installWrapper(dataDir);
    const result = await protectMcp({
      homeDir,
      dataDir,
      wrapperPath: wrapper.args[0],
      backendType: 'local',
    });

    // 2 clients scanned
    expect(result.clientsScanned).toBe(2);
    // 2 secrets (GITHUB_TOKEN + DATABASE_URL), filesystem server has no secrets
    expect(result.secretsFound).toBe(2);
    // 2 servers protected (github + db), filesystem skipped
    expect(result.serversProtected).toBe(2);

    // Verify filesystem server was NOT rewritten
    const cursorConfig = JSON.parse(fs.readFileSync(path.join(cursorDir, 'mcp.json'), 'utf-8'));
    expect(cursorConfig.mcpServers.filesystem.command).toBe('npx');
    expect(cursorConfig.mcpServers.filesystem.env.ROOT_DIR).toBe('/home/user');
  });
});
