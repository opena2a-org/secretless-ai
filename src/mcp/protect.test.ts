import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { protectMcp, type ProtectResult } from './protect';
import { McpVault } from './vault';
import { restoreConfig } from './rewrite';
import { createBackend, effectiveBackendName } from '../backends/factory';
import { LocalBackend } from '../backends/local';

// The store `local` is without a key, as effectiveBackendName names it, is the
// platform's: a test names it with a mock, so the case runs the same on every
// platform, and where the run then stores, builds an encrypted file in its
// place with createBackend. Every other call reaches the real function.
vi.mock('../backends/factory', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../backends/factory')>();
  return {
    ...actual,
    createBackend: vi.fn(actual.createBackend),
    effectiveBackendName: vi.fn(actual.effectiveBackendName),
  };
});

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

describe('protectMcp — ~/.claude.json (#470)', () => {
  let homeDir: string;
  let dataDir: string;
  let projectDir: string;
  let configPath: string;
  const wrapperPath = '/usr/local/bin/secretless-mcp';

  beforeEach(() => {
    homeDir = tmpDir();
    dataDir = tmpDir();
    projectDir = tmpDir();
    configPath = path.join(homeDir, '.claude.json');
  });
  afterEach(() => {
    cleanup(homeDir);
    cleanup(dataDir);
    cleanup(projectDir);
  });

  const protect = () => protectMcp({ homeDir, dataDir, projectDir, wrapperPath, backendType: 'local' });
  const vault = () => new McpVault({
    storeDir: path.join(dataDir, 'mcp-vault'),
    key: `${homeDir}-secretless-mcp-${process.env.USER ?? 'default'}`,
    backendType: 'local',
  });
  const server = (env: Record<string, string>) => ({ type: 'stdio', command: 'npx', args: ['some-mcp'], env });
  const wrapped = (name: string) => ({
    type: 'stdio',
    command: wrapperPath,
    args: ['--server', name, '--client', 'claude-code', '--', 'npx', 'some-mcp'],
    env: {},
  });

  it('protects the user-scope server at the top level and the local-scope server of a project, and backs the file up as it was', async () => {
    fs.writeFileSync(configPath, JSON.stringify({
      numStartups: 3,
      mcpServers: { github: server({ GITHUB_TOKEN: 'not-a-real-token-1' }) },
      projects: {
        '/work/app': { allowedTools: [], mcpServers: { slack: server({ SLACK_BOT_TOKEN: 'not-a-real-token-2' }) } },
        '/work/empty': { allowedTools: [], mcpServers: {} },
      },
    }, null, 2));
    const original = fs.readFileSync(configPath, 'utf-8');

    const result = await protect();

    expect(result.clientsScanned).toBe(1);
    expect(result.secretsFound).toBe(2);
    expect(result.serversProtected).toBe(2);
    expect(result.servers).toEqual([
      { client: 'claude-code', server: 'github', secretKeys: ['GITHUB_TOKEN'] },
      { client: 'claude-code', server: 'slack', secretKeys: ['SLACK_BOT_TOKEN'] },
    ]);
    expect(result.sharedName).toEqual([]);

    const config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    expect(config.numStartups).toBe(3);
    expect(config.mcpServers.github).toEqual(wrapped('github'));
    expect(config.projects['/work/app']).toEqual({ allowedTools: [], mcpServers: { slack: wrapped('slack') } });
    expect(config.projects['/work/empty']).toEqual({ allowedTools: [], mcpServers: {} });
    expect(await vault().getServerSecrets('claude-code', 'github')).toEqual({ GITHUB_TOKEN: 'not-a-real-token-1' });
    expect(await vault().getServerSecrets('claude-code', 'slack')).toEqual({ SLACK_BOT_TOKEN: 'not-a-real-token-2' });

    // One backup, of the file as it was before either map was rewritten.
    expect(restoreConfig(configPath, path.join(dataDir, 'mcp-backups'))).toBe(true);
    expect(fs.readFileSync(configPath, 'utf-8')).toBe(original);
  });

  it('leaves a project server named like the protected server at the top level as it is, and returns it', async () => {
    fs.writeFileSync(configPath, JSON.stringify({
      mcpServers: { github: server({ GITHUB_TOKEN: 'not-a-real-token-1' }) },
      projects: { '/work/app': { mcpServers: { github: server({ GITHUB_TOKEN: 'not-a-real-token-2' }) } } },
    }));

    const result = await protect();

    expect(result.servers).toEqual([{ client: 'claude-code', server: 'github', secretKeys: ['GITHUB_TOKEN'] }]);
    expect(result.secretsFound).toBe(1);
    expect(result.sharedName).toEqual([
      { client: 'claude-code', filePath: configPath, projectKey: '/work/app', server: 'github', protectedIn: { filePath: configPath } },
    ]);
    const config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    expect(config.mcpServers.github).toEqual(wrapped('github'));
    expect(config.projects['/work/app'].mcpServers.github).toEqual(server({ GITHUB_TOKEN: 'not-a-real-token-2' }));
    // The stored value is the protected server's, not overwritten by the other's.
    expect(await vault().getServerSecrets('claude-code', 'github')).toEqual({ GITHUB_TOKEN: 'not-a-real-token-1' });
  });

  it('leaves a server whose name a server protected before reads by, under a map key that differs from it', async () => {
    const before = JSON.stringify({
      mcpServers: {
        'github-personal': { command: wrapperPath, args: ['--server=github', '--client', 'claude-code', '--', 'npx', 'some-mcp'], env: {} },
      },
      projects: { '/work/app': { mcpServers: { github: server({ GITHUB_TOKEN: 'not-a-real-token-2' }) } } },
    });
    fs.writeFileSync(configPath, before);

    const result = await protect();

    expect(result.alreadyProtected).toBe(1);
    expect(result.secretsFound).toBe(0);
    expect(result.sharedName).toEqual([
      { client: 'claude-code', filePath: configPath, projectKey: '/work/app', server: 'github', protectedIn: { filePath: configPath } },
    ]);
    expect(fs.readFileSync(configPath, 'utf-8')).toBe(before);
  });

  it('leaves the server of the same name in the project .mcp.json, read after ~/.claude.json, as it is', async () => {
    fs.writeFileSync(configPath, JSON.stringify({ mcpServers: { github: server({ GITHUB_TOKEN: 'not-a-real-token-1' }) } }));
    const mcpJsonPath = path.join(projectDir, '.mcp.json');
    const mcpJson = JSON.stringify({ mcpServers: { github: server({ GITHUB_TOKEN: 'not-a-real-token-2' }) } });
    fs.writeFileSync(mcpJsonPath, mcpJson);

    const result = await protect();

    expect(result.servers).toEqual([{ client: 'claude-code', server: 'github', secretKeys: ['GITHUB_TOKEN'] }]);
    expect(result.sharedName).toEqual([
      { client: 'claude-code', filePath: mcpJsonPath, projectPath: '.mcp.json', server: 'github', protectedIn: { filePath: configPath } },
    ]);
    expect(fs.readFileSync(mcpJsonPath, 'utf-8')).toBe(mcpJson);
  });

  it('CONTROL: protects servers of the same name in the configs of two clients', async () => {
    fs.writeFileSync(configPath, JSON.stringify({ mcpServers: { github: server({ GITHUB_TOKEN: 'not-a-real-token-1' }) } }));
    fs.mkdirSync(path.join(homeDir, '.cursor'));
    fs.writeFileSync(path.join(homeDir, '.cursor', 'mcp.json'), JSON.stringify({ mcpServers: { github: server({ GITHUB_TOKEN: 'not-a-real-token-2' }) } }));

    const result = await protect();

    expect(result.servers.map((s) => `${s.client}/${s.server}`)).toEqual(['cursor/github', 'claude-code/github']);
    expect(result.sharedName).toEqual([]);
    expect(await vault().getServerSecrets('cursor', 'github')).toEqual({ GITHUB_TOKEN: 'not-a-real-token-2' });
    expect(await vault().getServerSecrets('claude-code', 'github')).toEqual({ GITHUB_TOKEN: 'not-a-real-token-1' });
  });
});

describe('protectMcp — clientsScanned counts clients, not configs or server maps (#484)', () => {
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

  const protect = () => protectMcp({ homeDir, dataDir, projectDir, wrapperPath: '/usr/local/bin/secretless-mcp', backendType: 'local' });
  const server = (env: Record<string, string>) => ({ type: 'stdio', command: 'npx', args: ['some-mcp'], env });
  const write = (dir: string, relativePath: string, content: unknown) => {
    const fullPath = path.join(dir, relativePath);
    fs.mkdirSync(path.dirname(fullPath), { recursive: true });
    fs.writeFileSync(fullPath, JSON.stringify(content));
  };

  it('counts ~/.claude.json with a user-scope server and the local-scope servers of two projects as one client', async () => {
    write(homeDir, '.claude.json', {
      mcpServers: { github: server({ GITHUB_TOKEN: 'not-a-real-token-1' }) },
      projects: {
        '/work/app': { mcpServers: { slack: server({ SLACK_BOT_TOKEN: 'not-a-real-token-2' }) } },
        '/work/api': { mcpServers: { db: server({ API_KEY: 'not-a-real-token-3' }) } },
      },
    });

    const result = await protect();

    expect(result.serversProtected).toBe(3);
    expect(result.clientsScanned).toBe(1);
  });

  it('counts ~/.claude/settings.json and the project .mcp.json as one client', async () => {
    write(homeDir, path.join('.claude', 'settings.json'), { mcpServers: { github: server({ GITHUB_TOKEN: 'not-a-real-token-1' }) } });
    write(projectDir, '.mcp.json', { mcpServers: { slack: server({ SLACK_BOT_TOKEN: 'not-a-real-token-2' }) } });

    const result = await protect();

    expect(result.serversProtected).toBe(2);
    expect(result.clientsScanned).toBe(1);
  });

  it('CONTROL: counts the configs of two clients as two', async () => {
    write(homeDir, '.claude.json', {
      mcpServers: { github: server({ GITHUB_TOKEN: 'not-a-real-token-1' }) },
      projects: { '/work/app': { mcpServers: { slack: server({ SLACK_BOT_TOKEN: 'not-a-real-token-2' }) } } },
    });
    write(homeDir, path.join('.cursor', 'mcp.json'), { mcpServers: { db: server({ API_KEY: 'not-a-real-token-3' }) } });

    const result = await protect();

    expect(result.serversProtected).toBe(3);
    expect(result.clientsScanned).toBe(2);
  });
});

describe('protectMcp — a secret in the env of a server that already runs through the wrapper (#508)', () => {
  let homeDir: string;
  let dataDir: string;
  let projectDir: string;
  let configPath: string;
  let savedHome: string | undefined;
  const wrapperPath = '/usr/local/bin/secretless-mcp';

  beforeEach(() => {
    homeDir = tmpDir();
    dataDir = tmpDir();
    projectDir = tmpDir();
    configPath = path.join(homeDir, '.cursor', 'mcp.json');
    fs.mkdirSync(path.dirname(configPath), { recursive: true });
    // The configured backend is read from HOME: this home configures none
    // unless a test writes its config.
    savedHome = process.env.HOME;
    process.env.HOME = homeDir;
  });
  afterEach(() => {
    vi.mocked(createBackend).mockReset();
    vi.mocked(effectiveBackendName).mockReset();
    if (savedHome === undefined) delete process.env.HOME;
    else process.env.HOME = savedHome;
    cleanup(homeDir);
    cleanup(dataDir);
    cleanup(projectDir);
  });

  const protect = () => protectMcp({ homeDir, dataDir, projectDir, wrapperPath, backendType: 'local' });
  const vault = () => new McpVault({
    storeDir: path.join(dataDir, 'mcp-vault'),
    key: `${homeDir}-secretless-mcp-${process.env.USER ?? 'default'}`,
    backendType: 'local',
  });
  const wrapped = (wrapperArgs: string[], env: Record<string, string>) => ({
    command: wrapperPath,
    args: [...wrapperArgs, '--', 'npx', 'some-mcp'],
    env,
  });
  const writeConfig = (servers: Record<string, unknown>): string => {
    const content = JSON.stringify({ mcpServers: servers });
    fs.writeFileSync(configPath, content);
    return content;
  };

  it('stores it under the --client and --server its wrapper reads by, beside the secrets stored there, and removes it from the env', async () => {
    await vault().storeServerSecrets('cursor', 'github', { GITHUB_TOKEN: 'not-a-real-token-1' });
    const server = wrapped(['--server', 'github', '--client', 'cursor'], { MY_SERVICE_API_KEY: 'FAKE-KEY-1234', LOG_LEVEL: 'debug' });
    writeConfig({ 'github-personal': server });

    const result = await protect();

    expect(result.secretsFound).toBe(1);
    expect(result.serversProtected).toBe(1);
    expect(result.alreadyProtected).toBe(0);
    expect(result.servers).toEqual([{ client: 'cursor', server: 'github-personal', secretKeys: ['MY_SERVICE_API_KEY'] }]);
    expect(result.unmoved).toEqual([]);
    // Its command and args are as they were: only the stored value left its env.
    const config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    expect(config.mcpServers['github-personal']).toEqual({ ...server, env: { LOG_LEVEL: 'debug' } });
    expect(await vault().getServerSecrets('cursor', 'github')).toEqual({
      GITHUB_TOKEN: 'not-a-real-token-1',
      MY_SERVICE_API_KEY: 'FAKE-KEY-1234',
    });
    // The file is backed up as it was, value included, for mcp-unprotect.
    expect(restoreConfig(configPath, path.join(dataDir, 'mcp-backups'))).toBe(true);
    expect(JSON.parse(fs.readFileSync(configPath, 'utf-8')).mcpServers['github-personal']).toEqual(server);
  });

  it('stores it for a server whose --backend argument names the backend this run stores in', async () => {
    writeConfig({ github: wrapped(['--server', 'github', '--client', 'cursor', '--backend', 'local'], { MY_SERVICE_API_KEY: 'FAKE-KEY-1234' }) });

    const result = await protect();

    expect(result.unmoved).toEqual([]);
    expect(result.secretsFound).toBe(1);
    expect(JSON.parse(fs.readFileSync(configPath, 'utf-8')).mcpServers.github.env).toEqual({});
    expect(await vault().getServerSecrets('cursor', 'github')).toEqual({ MY_SERVICE_API_KEY: 'FAKE-KEY-1234' });
  });

  it('leaves it, and returns the server, when another protected server reads its secrets by the same name', async () => {
    const before = writeConfig({
      github: wrapped(['--server', 'github', '--client', 'cursor'], { MY_SERVICE_API_KEY: 'FAKE-KEY-1234' }),
      'github-work': wrapped(['--server=github', '--client', 'cursor'], {}),
    });

    const result = await protect();

    expect(result.secretsFound).toBe(0);
    expect(result.alreadyProtected).toBe(1);
    expect(result.unmoved).toEqual([{
      client: 'cursor',
      filePath: configPath,
      server: 'github',
      reason: 'another protected server reads its secrets by the same name, cursor/github',
    }]);
    expect(fs.readFileSync(configPath, 'utf-8')).toBe(before);
    expect(await vault().getServerSecrets('cursor', 'github')).toEqual({});
  });

  it('leaves it when the other protected server reading by the same name is in a project-level config it does not rewrite', async () => {
    const before = writeConfig({ github: wrapped(['--server', 'github', '--client', 'cursor'], { MY_SERVICE_API_KEY: 'FAKE-KEY-1234' }) });
    const projectConfig = path.join(projectDir, '.cursor', 'mcp.json');
    fs.mkdirSync(path.dirname(projectConfig), { recursive: true });
    fs.writeFileSync(projectConfig, JSON.stringify({ mcpServers: { repoTool: wrapped(['--server', 'github', '--client', 'cursor'], {}) } }));

    const result = await protect();

    expect(result.secretsFound).toBe(0);
    expect(result.unmoved).toEqual([{
      client: 'cursor',
      filePath: configPath,
      server: 'github',
      reason: 'another protected server reads its secrets by the same name, cursor/github',
    }]);
    expect(result.projectLevel).toEqual([{ client: 'cursor', filePath: projectConfig, projectPath: path.join('.cursor', 'mcp.json') }]);
    expect(fs.readFileSync(configPath, 'utf-8')).toBe(before);
    expect(await vault().getServerSecrets('cursor', 'github')).toEqual({});
  });

  it('leaves it when its --backend argument names a backend other than the one this run stores in', async () => {
    const before = writeConfig({
      github: wrapped(['--server', 'github', '--client', 'cursor', '--backend', '1password'], { MY_SERVICE_API_KEY: 'FAKE-KEY-1234' }),
    });

    const result = await protect();

    expect(result.secretsFound).toBe(0);
    expect(result.unmoved).toEqual([{
      client: 'cursor',
      filePath: configPath,
      server: 'github',
      reason: 'its --backend argument is "1password", and this run stores in local',
    }]);
    expect(fs.readFileSync(configPath, 'utf-8')).toBe(before);
  });

  it('leaves it when it gives no --backend and the configured backend is not the one this run stores in', async () => {
    fs.mkdirSync(path.join(homeDir, '.secretless-ai'), { recursive: true });
    fs.writeFileSync(path.join(homeDir, '.secretless-ai', 'config.json'), JSON.stringify({ backend: '1password' }));
    const before = writeConfig({ github: wrapped(['--server', 'github', '--client', 'cursor'], { MY_SERVICE_API_KEY: 'FAKE-KEY-1234' }) });

    const result = await protect();

    expect(result.unmoved.map((server) => server.reason)).toEqual([
      'its wrapper reads from the configured backend, 1password, and this run stores in local',
    ]);
    expect(fs.readFileSync(configPath, 'utf-8')).toBe(before);
  });

  it('stores it in the platform keychain, where its wrapper reads local, when this run is given no home directory and no backend is configured (#513)', async () => {
    // As protect-mcp runs, with no home directory given: the vault has no key,
    // and neither has the store of a wrapper whose args name no --vault-dir or
    // --vault-key, so with no backend configured both build `local`, named or
    // not, as the platform keychain where there is one. That keychain is
    // named here, and this run's store is an encrypted file standing in for
    // it. Until #513 the wrapper gave its store a key and read `local` from
    // the encrypted file, and these cases were left in the env.
    vi.mocked(effectiveBackendName).mockImplementation((type) => (type === 'local' ? 'keychain-macos' : type));
    vi.mocked(createBackend).mockImplementation((_type, config) => new LocalBackend({ ...config, key: 'not-a-real-key' }));
    const cases: Array<{ backendType?: 'local'; wrapperArgs: string[] }> = [
      { wrapperArgs: [] },
      { wrapperArgs: ['--backend', 'local'] },
      { backendType: 'local', wrapperArgs: [] },
    ];
    for (const { backendType, wrapperArgs } of cases) {
      writeConfig({
        github: wrapped(['--server', 'github', '--client', 'cursor', ...wrapperArgs], { MY_SERVICE_API_KEY: 'FAKE-KEY-1234' }),
      });

      const result = await protectMcp({ dataDir, projectDir, wrapperPath, ...(backendType ? { backendType } : {}) });

      expect(result.unmoved).toEqual([]);
      expect(result.secretsFound).toBe(1);
      expect(JSON.parse(fs.readFileSync(configPath, 'utf-8')).mcpServers.github.env).toEqual({});
    }
    const standIn = new McpVault({ backend: new LocalBackend({ storeDir: path.join(dataDir, 'mcp-vault'), key: 'not-a-real-key' }) });
    expect(await standIn.getServerSecrets('cursor', 'github')).toEqual({ MY_SERVICE_API_KEY: 'FAKE-KEY-1234' });
  });

  it('CONTROL: stores it when a home directory is given, as the vault then has a key and is the encrypted file for local', async () => {
    vi.mocked(effectiveBackendName).mockReturnValue('keychain-macos');
    writeConfig({ github: wrapped(['--server', 'github', '--client', 'cursor'], { MY_SERVICE_API_KEY: 'FAKE-KEY-1234' }) });

    const result = await protect();

    expect(result.unmoved).toEqual([]);
    expect(result.secretsFound).toBe(1);
    expect(await vault().getServerSecrets('cursor', 'github')).toEqual({ MY_SERVICE_API_KEY: 'FAKE-KEY-1234' });
  });

  it('leaves it when another value is stored under the same env name for the name its wrapper reads by', async () => {
    // The wrapper gives the server the stored value in place of the one in its
    // env, so storing this one would change the credential the server is given.
    await vault().storeServerSecrets('cursor', 'github', { MY_SERVICE_API_KEY: 'FAKE-KEY-1234' });
    const before = writeConfig({
      github: wrapped(['--server', 'github', '--client', 'cursor'], { MY_SERVICE_API_KEY: 'FAKE-KEY-5678', OTHER_API_KEY: 'FAKE-KEY-9012' }),
    });

    const result = await protect();

    expect(result.secretsFound).toBe(0);
    expect(result.unmoved).toEqual([{
      client: 'cursor',
      filePath: configPath,
      server: 'github',
      reason: 'MY_SERVICE_API_KEY is stored under cursor/github with another value, which its wrapper gives the server in place of the one in its env',
    }]);
    expect(fs.readFileSync(configPath, 'utf-8')).toBe(before);
    expect(await vault().getServerSecrets('cursor', 'github')).toEqual({ MY_SERVICE_API_KEY: 'FAKE-KEY-1234' });
  });

  it('CONTROL: stores it when the value stored under the same env name is the same value', async () => {
    await vault().storeServerSecrets('cursor', 'github', { MY_SERVICE_API_KEY: 'FAKE-KEY-1234' });
    writeConfig({ github: wrapped(['--server', 'github', '--client', 'cursor'], { MY_SERVICE_API_KEY: 'FAKE-KEY-1234' }) });

    const result = await protect();

    expect(result.unmoved).toEqual([]);
    expect(result.secretsFound).toBe(1);
    expect(JSON.parse(fs.readFileSync(configPath, 'utf-8')).mcpServers.github.env).toEqual({});
    expect(await vault().getServerSecrets('cursor', 'github')).toEqual({ MY_SERVICE_API_KEY: 'FAKE-KEY-1234' });
  });

  it('leaves it when its args choose the store its wrapper reads from with --vault-dir or --vault-key', async () => {
    for (const storeFlag of [['--vault-dir', path.join(dataDir, 'other-vault')], ['--vault-key', 'not-a-real-key']]) {
      const before = writeConfig({
        github: wrapped(['--server', 'github', '--client', 'cursor', ...storeFlag], { MY_SERVICE_API_KEY: 'FAKE-KEY-1234' }),
      });

      const result = await protect();

      expect(result.unmoved.map((server) => server.reason)).toEqual([
        'its args choose the store its wrapper reads from with --vault-dir or --vault-key',
      ]);
      expect(fs.readFileSync(configPath, 'utf-8')).toBe(before);
    }
  });

  it('CONTROL: counts a server with no secret in its env as already protected and leaves the file as it is', async () => {
    const before = writeConfig({ github: wrapped(['--server', 'github', '--client', 'cursor'], { LOG_LEVEL: 'debug' }) });

    const result = await protect();

    expect(result.alreadyProtected).toBe(1);
    expect(result.secretsFound).toBe(0);
    expect(result.unmoved).toEqual([]);
    expect(fs.readFileSync(configPath, 'utf-8')).toBe(before);
  });
});
