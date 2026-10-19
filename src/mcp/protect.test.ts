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
    expect(result.unchecked).toEqual([]);
  });

  it('returns each server with a part it could not read, and still protects the secret it did read', async () => {
    const configPath = path.join(homeDir, '.cursor', 'mcp.json');
    fs.mkdirSync(path.dirname(configPath), { recursive: true });
    fs.writeFileSync(
      configPath,
      JSON.stringify({
        mcpServers: {
          github: { command: 'npx', env: { GITHUB_TOKEN: 'not-a-real-token', API_TOKEN: 1234 } },
          db: { command: 'npx', env: 'not-an-object' },
        },
      })
    );

    const result = await protectMcp({
      homeDir,
      dataDir,
      wrapperPath: '/usr/local/bin/secretless-mcp',
      backendType: 'local',
    });

    expect(result.servers).toEqual([{ client: 'cursor', server: 'github', secretKeys: ['GITHUB_TOKEN'] }]);
    expect(result.unchecked).toEqual([
      {
        client: 'cursor',
        filePath: configPath,
        servers: [
          { name: 'github', part: 'env value API_TOKEN', reason: 'not a string' },
          { name: 'db', part: 'env', reason: 'not a JSON object' },
        ],
      },
    ]);

    const config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    expect(config.mcpServers.github.env).not.toHaveProperty('GITHUB_TOKEN');
    expect(config.mcpServers.db.env).toBe('not-an-object');
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

  it('leaves a config untouched when a secret in it cannot be stored', async () => {
    const configDir = path.join(homeDir, '.cursor');
    fs.mkdirSync(configDir, { recursive: true });
    const configPath = path.join(configDir, 'mcp.json');
    const original = JSON.stringify({
      mcpServers: {
        github: {
          command: 'npx',
          args: ['@github/mcp-server'],
          env: { GITHUB_TOKEN: '\x1b[200~ghp_FAKE23def456ghi789jkl012mno345pqr678\x1b[201~' },
        },
      },
    });
    fs.writeFileSync(configPath, original);

    await expect(protectMcp({
      homeDir,
      dataDir,
      wrapperPath: '/usr/local/bin/secretless-mcp',
      backendType: 'local',
    })).rejects.toThrow(/"GITHUB_TOKEN" for MCP server cursor\/github was not stored/);

    // Rewriting would point the server at a vault entry holding the mangled
    // capture; the plaintext config is the one copy of what the user wrote.
    expect(fs.readFileSync(configPath, 'utf-8')).toBe(original);
  });

  it('refuses an 8-bit CSI in a server value and leaves the config untouched (#230)', async () => {
    const configDir = path.join(homeDir, '.cursor');
    fs.mkdirSync(configDir, { recursive: true });
    const configPath = path.join(configDir, 'mcp.json');
    // U+009B is ESC [ as one character; the 7-bit form is refused above.
    const original = JSON.stringify({
      mcpServers: {
        github: {
          command: 'npx',
          args: ['@github/mcp-server'],
          env: { GITHUB_TOKEN: 'ghp_FAKE23def456ghi789jkl012mno345pqr678\u009b[2J' },
        },
      },
    });
    fs.writeFileSync(configPath, original);

    await expect(protectMcp({
      homeDir,
      dataDir,
      wrapperPath: '/usr/local/bin/secretless-mcp',
      backendType: 'local',
    })).rejects.toThrow(/"GITHUB_TOKEN" for MCP server cursor\/github was not stored: the value contains a C1 control character \(U\+009B\)/);

    expect(fs.readFileSync(configPath, 'utf-8')).toBe(original);
  });
});

describe('protectMcp — project-level client configs', () => {
  let homeDir: string;
  let dataDir: string;
  let projectDir: string;

  beforeEach(() => {
    homeDir = tmpDir();
    dataDir = tmpDir();
    projectDir = tmpDir();
  });
  afterEach(() => {
    cleanup(homeDir);
    cleanup(dataDir);
    cleanup(projectDir);
  });

  // A Slack-shaped bot token, built at runtime so the file holds no token literal.
  const slackToken = ['xox', 'b-1234567890-1234567890-', 'FAKEabcdefghijklmnopqrst'].join('');

  function write(baseDir: string, relativePath: string, content: string): string {
    const fullPath = path.join(baseDir, relativePath);
    fs.mkdirSync(path.dirname(fullPath), { recursive: true });
    fs.writeFileSync(fullPath, content);
    return fullPath;
  }

  const protect = () => protectMcp({
    homeDir,
    dataDir,
    projectDir,
    wrapperPath: '/usr/local/bin/secretless-mcp',
    backendType: 'local',
  });

  it('leaves .cursor/mcp.json and .vscode/mcp.json in the project as they are, and returns them', async () => {
    const cursor = JSON.stringify({ mcpServers: { slack: { command: 'npx', env: { SLACK_BOT_TOKEN: slackToken } } } });
    const vscode = JSON.stringify({ servers: { slack: { type: 'stdio', command: 'npx', env: { SLACK_BOT_TOKEN: slackToken } } } });
    const cursorPath = write(projectDir, '.cursor/mcp.json', cursor);
    const vscodePath = write(projectDir, '.vscode/mcp.json', vscode);

    const result = await protect();

    expect(result.clientsScanned).toBe(0);
    expect(result.secretsFound).toBe(0);
    expect(result.servers).toEqual([]);
    expect(result.projectLevel).toEqual([
      { client: 'cursor', filePath: cursorPath, projectPath: path.join('.cursor', 'mcp.json') },
      { client: 'vscode', filePath: vscodePath, projectPath: path.join('.vscode', 'mcp.json') },
    ]);
    expect(fs.readFileSync(cursorPath, 'utf-8')).toBe(cursor);
    expect(fs.readFileSync(vscodePath, 'utf-8')).toBe(vscode);
  });

  it('returns a project-level config it could not parse with the others it leaves, not as one to fix and protect', async () => {
    const configPath = write(projectDir, 'mcp.json', '{\n  "mcpServers": {\n    "gh": { "command": "npx" },\n  }\n}\n');

    const result = await protect();

    expect(result.unparsed).toEqual([]);
    expect(result.projectLevel).toEqual([{ client: 'unknown', filePath: configPath, projectPath: 'mcp.json' }]);
  });

  it('CONTROL: still rewrites the project .mcp.json', async () => {
    const configPath = write(
      projectDir,
      '.mcp.json',
      JSON.stringify({ mcpServers: { slack: { command: 'npx', env: { SLACK_BOT_TOKEN: slackToken } } } }),
    );

    const result = await protect();

    expect(result.clientsScanned).toBe(1);
    expect(result.secretsFound).toBe(1);
    expect(result.serversProtected).toBe(1);
    expect(result.projectLevel).toEqual([]);
    const config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    expect(config.mcpServers.slack.command).toBe('/usr/local/bin/secretless-mcp');
    expect(config.mcpServers.slack.env).not.toHaveProperty('SLACK_BOT_TOKEN');
  });

  it('rewrites a home VS Code config under the servers key it read the secret from', async () => {
    const configPath = write(
      homeDir,
      '.vscode/mcp.json',
      JSON.stringify({ servers: { slack: { type: 'stdio', command: 'npx', args: ['slack-mcp'], env: { SLACK_BOT_TOKEN: slackToken, SLACK_TEAM_ID: 'T0FAKE' } } } }),
    );

    const result = await protect();

    expect(result.servers).toEqual([{ client: 'vscode', server: 'slack', secretKeys: ['SLACK_BOT_TOKEN'] }]);
    expect(result.serversProtected).toBe(1);
    const config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    expect(config).not.toHaveProperty('mcpServers');
    expect(config.servers.slack.type).toBe('stdio');
    expect(config.servers.slack.command).toBe('/usr/local/bin/secretless-mcp');
    expect(config.servers.slack.args).toEqual(['--server', 'slack', '--client', 'vscode', '--', 'npx', 'slack-mcp']);
    expect(config.servers.slack.env).toEqual({ SLACK_TEAM_ID: 'T0FAKE' });
  });

  it('rewrites a config whose server map is under mcp-servers, the key its secret was read from', async () => {
    const configPath = write(
      homeDir,
      '.cursor/mcp.json',
      JSON.stringify({ 'mcp-servers': { slack: { command: 'npx', env: { SLACK_BOT_TOKEN: slackToken } } } }),
    );

    const result = await protect();

    expect(result.secretsFound).toBe(1);
    expect(result.serversProtected).toBe(1);
    const config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    expect(config['mcp-servers'].slack.command).toBe('/usr/local/bin/secretless-mcp');
    expect(config['mcp-servers'].slack.env).toEqual({});
    expect(fs.readFileSync(configPath, 'utf-8')).not.toContain(slackToken);
  });
});
