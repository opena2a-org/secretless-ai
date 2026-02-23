import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { protectMcp, type ProtectResult } from './protect';

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-mcp-protect-'));
}

function cleanup(dir: string): void {
  fs.rmSync(dir, { recursive: true, force: true });
}

describe('protectMcp', () => {
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

  it('protects a Cursor config with plaintext secrets', async () => {
    const configDir = path.join(homeDir, '.cursor');
    fs.mkdirSync(configDir, { recursive: true });
    fs.writeFileSync(
      path.join(configDir, 'mcp.json'),
      JSON.stringify({
        mcpServers: {
          github: {
            command: 'npx',
            args: ['@github/mcp-server'],
            env: {
              GITHUB_TOKEN: 'ghp_abc123def456ghi789jkl012mno345pqr678',
              GITHUB_ORG: 'my-org',
            },
          },
        },
      })
    );

    const result = await protectMcp({
      homeDir,
      dataDir,
      wrapperPath: '/usr/local/bin/secretless-mcp',
      backendType: 'local',
    });

    expect(result.clientsScanned).toBeGreaterThan(0);
    expect(result.secretsFound).toBe(1);
    expect(result.serversProtected).toBe(1);

    // Config should be rewritten
    const config = JSON.parse(fs.readFileSync(path.join(configDir, 'mcp.json'), 'utf-8'));
    expect(config.mcpServers.github.command).toBe('/usr/local/bin/secretless-mcp');
    expect(config.mcpServers.github.env).not.toHaveProperty('GITHUB_TOKEN');
    expect(config.mcpServers.github.env.GITHUB_ORG).toBe('my-org');
  });

  it('reports when no configs found', async () => {
    const result = await protectMcp({
      homeDir,
      dataDir,
      wrapperPath: '/usr/local/bin/secretless-mcp',
      backendType: 'local',
    });

    expect(result.clientsScanned).toBe(0);
    expect(result.secretsFound).toBe(0);
  });

  it('reports when configs have no secrets', async () => {
    const configDir = path.join(homeDir, '.cursor');
    fs.mkdirSync(configDir, { recursive: true });
    fs.writeFileSync(
      path.join(configDir, 'mcp.json'),
      JSON.stringify({
        mcpServers: {
          filesystem: {
            command: 'npx',
            args: ['@modelcontextprotocol/server-filesystem'],
            env: {},
          },
        },
      })
    );

    const result = await protectMcp({
      homeDir,
      dataDir,
      wrapperPath: '/usr/local/bin/secretless-mcp',
      backendType: 'local',
    });

    expect(result.clientsScanned).toBe(1);
    expect(result.secretsFound).toBe(0);
    expect(result.serversProtected).toBe(0);
  });

  it('protects multiple servers across multiple clients', async () => {
    // Cursor
    const cursorDir = path.join(homeDir, '.cursor');
    fs.mkdirSync(cursorDir, { recursive: true });
    fs.writeFileSync(
      path.join(cursorDir, 'mcp.json'),
      JSON.stringify({
        mcpServers: {
          github: { command: 'npx', args: ['gh-mcp'], env: { GITHUB_TOKEN: 'ghp_1234567890abcdef1234567890abcdef12345678' } },
          slack: { command: 'npx', args: ['slack-mcp'], env: { SLACK_BOT_TOKEN: 'test-slack-bot-token-placeholder-value' } },
        },
      })
    );

    // Claude Code
    const claudeDir = path.join(homeDir, '.claude');
    fs.mkdirSync(claudeDir, { recursive: true });
    fs.writeFileSync(
      path.join(claudeDir, 'settings.json'),
      JSON.stringify({
        mcpServers: {
          db: { command: 'npx', args: ['pg-mcp'], env: { DATABASE_URL: 'postgres://user:pass@host/db' } },
        },
      })
    );

    const result = await protectMcp({
      homeDir,
      dataDir,
      wrapperPath: '/usr/local/bin/secretless-mcp',
      backendType: 'local',
    });

    expect(result.clientsScanned).toBe(2);
    expect(result.secretsFound).toBe(3);
    expect(result.serversProtected).toBe(3);
  });

  it('skips already-protected servers', async () => {
    const configDir = path.join(homeDir, '.cursor');
    fs.mkdirSync(configDir, { recursive: true });
    fs.writeFileSync(
      path.join(configDir, 'mcp.json'),
      JSON.stringify({
        mcpServers: {
          already: { command: 'secretless-mcp', args: ['--server', 'already', '--', 'npx', 'test'], env: {} },
          raw: { command: 'npx', args: ['test'], env: { API_KEY: 'secret' } },
        },
      })
    );

    const result = await protectMcp({
      homeDir,
      dataDir,
      wrapperPath: '/usr/local/bin/secretless-mcp',
      backendType: 'local',
    });

    expect(result.serversProtected).toBe(1); // Only 'raw', not 'already'
  });
});
