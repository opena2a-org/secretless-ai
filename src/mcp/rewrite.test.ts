import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { rewriteConfig, restoreConfig, RewriteResult } from './rewrite';

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-rewrite-test-'));
}

function cleanup(dir: string): void {
  fs.rmSync(dir, { recursive: true, force: true });
}

/** Helper to write a JSON config file, creating parent dirs as needed. */
function writeConfig(filePath: string, content: Record<string, unknown>): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(content, null, 2));
}

/** Standard config fixture with one server that has secrets. */
function makeConfig(): Record<string, unknown> {
  return {
    mcpServers: {
      'jira-server': {
        command: 'npx',
        args: ['-y', '@modelcontextprotocol/server-jira'],
        env: {
          JIRA_URL: 'https://mycompany.atlassian.net',
          JIRA_API_TOKEN: 'secret-token-123',
        },
      },
    },
  };
}

describe('rewriteConfig', () => {
  let dir: string;
  let backupDir: string;
  const wrapperPath = '/usr/local/bin/secretless-mcp';

  beforeEach(() => {
    dir = tmpDir();
    backupDir = path.join(dir, 'backups');
  });
  afterEach(() => { cleanup(dir); });

  it('rewrites a single server config', () => {
    const configPath = path.join(dir, 'mcp.json');
    writeConfig(configPath, makeConfig());

    const secrets: Record<string, Record<string, string>> = {
      'jira-server': { JIRA_API_TOKEN: 'secret-token-123' },
    };

    const result = rewriteConfig(configPath, 'cursor', secrets, wrapperPath, backupDir);

    expect(result.serversRewritten).toBe(1);
    expect(result.backupPath).toBeTruthy();

    // Verify rewritten config
    const rewritten = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    const server = rewritten.mcpServers['jira-server'];
    expect(server.command).toBe(wrapperPath);
    expect(server.args).toEqual([
      '--server', 'jira-server',
      '--client', 'cursor',
      '--', 'npx', '-y', '@modelcontextprotocol/server-jira',
    ]);
    // Secret env var removed, non-secret kept
    expect(server.env).toEqual({ JIRA_URL: 'https://mycompany.atlassian.net' });
  });

  it('creates a backup of the original config', () => {
    const configPath = path.join(dir, 'mcp.json');
    const originalConfig = makeConfig();
    writeConfig(configPath, originalConfig);

    const secrets: Record<string, Record<string, string>> = {
      'jira-server': { JIRA_API_TOKEN: 'secret-token-123' },
    };

    const result = rewriteConfig(configPath, 'cursor', secrets, wrapperPath, backupDir);

    expect(result.backupPath).toBeTruthy();
    expect(fs.existsSync(result.backupPath!)).toBe(true);

    // Backup is encrypted — verify by restoring it
    const restored = restoreConfig(configPath, backupDir);
    expect(restored).toBe(true);
    const restoredContent = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    expect(restoredContent).toEqual(originalConfig);
  });

  it('skips servers with no secrets to protect', () => {
    const configPath = path.join(dir, 'mcp.json');
    writeConfig(configPath, {
      mcpServers: {
        'no-secrets-server': {
          command: 'node',
          args: ['server.js'],
          env: { HOME: '/Users/test' },
        },
      },
    });

    // Empty secrets map — no server has secrets
    const secrets: Record<string, Record<string, string>> = {};

    const result = rewriteConfig(configPath, 'cursor', secrets, wrapperPath, backupDir);

    expect(result.serversRewritten).toBe(0);
    // Config should be unchanged since nothing was rewritten
    const config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    expect(config.mcpServers['no-secrets-server'].command).toBe('node');
  });

  it('skips already-protected servers', () => {
    const configPath = path.join(dir, 'mcp.json');
    writeConfig(configPath, {
      mcpServers: {
        'already-protected': {
          command: 'secretless-mcp',
          args: ['--server', 'my-server', '--client', 'cursor', '--', 'npx', 'some-server'],
          env: {},
        },
      },
    });

    const secrets: Record<string, Record<string, string>> = {
      'already-protected': { SOME_KEY: 'value' },
    };

    const result = rewriteConfig(configPath, 'cursor', secrets, wrapperPath, backupDir);

    expect(result.serversRewritten).toBe(0);
    // Command should still be secretless-mcp (unchanged)
    const config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    expect(config.mcpServers['already-protected'].command).toBe('secretless-mcp');
  });

  it('skips servers protected with full path command', () => {
    const configPath = path.join(dir, 'mcp.json');
    writeConfig(configPath, {
      mcpServers: {
        'path-protected': {
          command: '/usr/local/bin/secretless-mcp',
          args: ['--server', 'my-server', '--client', 'cursor', '--', 'npx', 'some-server'],
          env: {},
        },
      },
    });

    const secrets: Record<string, Record<string, string>> = {
      'path-protected': { SOME_KEY: 'value' },
    };

    const result = rewriteConfig(configPath, 'cursor', secrets, wrapperPath, backupDir);

    expect(result.serversRewritten).toBe(0);
  });

  it('skips servers where command matches wrapperPath exactly', () => {
    const customWrapper = '/home/user/.local/bin/my-wrapper';
    const configPath = path.join(dir, 'mcp.json');
    writeConfig(configPath, {
      mcpServers: {
        'custom-wrapped': {
          command: customWrapper,
          args: ['--server', 'my-server', '--', 'npx', 'some-server'],
          env: {},
        },
      },
    });

    const secrets: Record<string, Record<string, string>> = {
      'custom-wrapped': { SOME_KEY: 'value' },
    };

    const result = rewriteConfig(configPath, 'cursor', secrets, customWrapper, backupDir);

    expect(result.serversRewritten).toBe(0);
  });

  it('preserves other config keys outside mcpServers', () => {
    const configPath = path.join(dir, 'mcp.json');
    writeConfig(configPath, {
      theme: 'dark',
      otherStuff: { nested: true },
      mcpServers: {
        'jira-server': {
          command: 'npx',
          args: ['-y', '@modelcontextprotocol/server-jira'],
          env: { JIRA_API_TOKEN: 'secret-token-123' },
        },
      },
    });

    const secrets: Record<string, Record<string, string>> = {
      'jira-server': { JIRA_API_TOKEN: 'secret-token-123' },
    };

    const result = rewriteConfig(configPath, 'cursor', secrets, wrapperPath, backupDir);

    expect(result.serversRewritten).toBe(1);
    const config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    expect(config.theme).toBe('dark');
    expect(config.otherStuff).toEqual({ nested: true });
  });

  it('writes config with mode 0o600', () => {
    const configPath = path.join(dir, 'mcp.json');
    writeConfig(configPath, makeConfig());

    const secrets: Record<string, Record<string, string>> = {
      'jira-server': { JIRA_API_TOKEN: 'secret-token-123' },
    };

    rewriteConfig(configPath, 'cursor', secrets, wrapperPath, backupDir);

    const stats = fs.statSync(configPath);
    // Check owner permissions (0o600 = rw-------)
    const mode = stats.mode & 0o777;
    expect(mode).toBe(0o600);
  });

  it('creates manifest.json mapping configPath to backup', () => {
    const configPath = path.join(dir, 'mcp.json');
    writeConfig(configPath, makeConfig());

    const secrets: Record<string, Record<string, string>> = {
      'jira-server': { JIRA_API_TOKEN: 'secret-token-123' },
    };

    const result = rewriteConfig(configPath, 'cursor', secrets, wrapperPath, backupDir);

    const manifestPath = path.join(backupDir, 'manifest.json');
    expect(fs.existsSync(manifestPath)).toBe(true);

    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf-8'));
    expect(manifest[configPath]).toBe(result.backupPath);
  });

  it('returns null backupPath when no servers are rewritten', () => {
    const configPath = path.join(dir, 'mcp.json');
    writeConfig(configPath, {
      mcpServers: {
        'no-secrets': {
          command: 'node',
          args: ['server.js'],
          env: {},
        },
      },
    });

    const secrets: Record<string, Record<string, string>> = {};

    const result = rewriteConfig(configPath, 'cursor', secrets, wrapperPath, backupDir);

    expect(result.serversRewritten).toBe(0);
    expect(result.backupPath).toBeNull();
  });

  it('removes all secret env vars and keeps non-secret ones', () => {
    const configPath = path.join(dir, 'mcp.json');
    writeConfig(configPath, {
      mcpServers: {
        'multi-env': {
          command: 'npx',
          args: ['server'],
          env: {
            BASE_URL: 'https://api.example.com',
            API_KEY: 'secret-key',
            API_SECRET: 'secret-value',
            DEBUG: 'true',
          },
        },
      },
    });

    const secrets: Record<string, Record<string, string>> = {
      'multi-env': {
        API_KEY: 'secret-key',
        API_SECRET: 'secret-value',
      },
    };

    rewriteConfig(configPath, 'cursor', secrets, wrapperPath, backupDir);

    const config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    const server = config.mcpServers['multi-env'];
    expect(server.env).toEqual({
      BASE_URL: 'https://api.example.com',
      DEBUG: 'true',
    });
  });
});

describe('restoreConfig', () => {
  let dir: string;
  let backupDir: string;
  const wrapperPath = '/usr/local/bin/secretless-mcp';

  beforeEach(() => {
    dir = tmpDir();
    backupDir = path.join(dir, 'backups');
  });
  afterEach(() => { cleanup(dir); });

  it('restores config from backup', () => {
    const configPath = path.join(dir, 'mcp.json');
    const originalConfig = makeConfig();
    writeConfig(configPath, originalConfig);

    // First, rewrite (which creates a backup)
    const secrets: Record<string, Record<string, string>> = {
      'jira-server': { JIRA_API_TOKEN: 'secret-token-123' },
    };
    rewriteConfig(configPath, 'cursor', secrets, wrapperPath, backupDir);

    // Verify it was rewritten
    const rewritten = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    expect(rewritten.mcpServers['jira-server'].command).toBe(wrapperPath);

    // Now restore
    const restored = restoreConfig(configPath, backupDir);
    expect(restored).toBe(true);

    // Verify original content is back
    const restoredContent = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    expect(restoredContent).toEqual(originalConfig);
  });

  it('returns false when no backup exists', () => {
    const configPath = path.join(dir, 'nonexistent.json');
    const restored = restoreConfig(configPath, backupDir);
    expect(restored).toBe(false);
  });

  it('returns false when backup dir does not exist', () => {
    const configPath = path.join(dir, 'mcp.json');
    const nonExistentBackupDir = path.join(dir, 'no-such-dir');
    const restored = restoreConfig(configPath, nonExistentBackupDir);
    expect(restored).toBe(false);
  });
});
