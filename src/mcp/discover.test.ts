import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { discoverMcpConfigs, discoverMcpConfigsDetailed, mcpConfigLocations, McpConfigFile } from './discover';
import { CONFIG_FILES } from '../patterns';

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-mcp-test-'));
}

function cleanup(dir: string): void {
  fs.rmSync(dir, { recursive: true, force: true });
}

/** Helper to write a JSON config file, creating parent dirs as needed. */
function writeConfig(baseDir: string, relativePath: string, content: Record<string, unknown>): void {
  const fullPath = path.join(baseDir, relativePath);
  fs.mkdirSync(path.dirname(fullPath), { recursive: true });
  fs.writeFileSync(fullPath, JSON.stringify(content, null, 2));
}

/** Standard mcpServers fixture with one unprotected and one protected server. */
function makeMcpServers(extra?: Record<string, unknown>): Record<string, unknown> {
  return {
    mcpServers: {
      'my-server': {
        command: 'npx',
        args: ['-y', '@modelcontextprotocol/server-filesystem'],
        env: { HOME: '/Users/test' },
      },
      'protected-server': {
        command: 'secretless-mcp',
        args: ['--', 'npx', '-y', '@modelcontextprotocol/server-filesystem'],
        env: { ANTHROPIC_API_KEY: 'redacted' },
      },
      ...extra,
    },
  };
}

describe('discoverMcpConfigs', () => {
  let dir: string;

  beforeEach(() => { dir = tmpDir(); });
  afterEach(() => { cleanup(dir); });

  it('finds Claude Desktop config on macOS', () => {
    const configPath = path.join('Library', 'Application Support', 'Claude', 'claude_desktop_config.json');
    writeConfig(dir, configPath, makeMcpServers());

    const results = discoverMcpConfigs(dir);

    const claudeDesktop = results.find(r => r.client === 'claude-desktop');
    expect(claudeDesktop).toBeDefined();
    expect(claudeDesktop!.filePath).toBe(path.join(dir, configPath));
    expect(claudeDesktop!.servers).toHaveLength(2);

    const unprotected = claudeDesktop!.servers.find(s => s.name === 'my-server');
    expect(unprotected).toBeDefined();
    expect(unprotected!.command).toBe('npx');
    expect(unprotected!.alreadyProtected).toBe(false);
  });

  it('finds Cursor config', () => {
    writeConfig(dir, '.cursor/mcp.json', makeMcpServers());

    const results = discoverMcpConfigs(dir);

    const cursor = results.find(r => r.client === 'cursor');
    expect(cursor).toBeDefined();
    expect(cursor!.filePath).toBe(path.join(dir, '.cursor', 'mcp.json'));
    expect(cursor!.servers).toHaveLength(2);
  });

  it('finds Claude Code settings.json config', () => {
    writeConfig(dir, '.claude/settings.json', makeMcpServers());

    const results = discoverMcpConfigs(dir);

    const claudeCode = results.find(r => r.client === 'claude-code');
    expect(claudeCode).toBeDefined();
    expect(claudeCode!.filePath).toBe(path.join(dir, '.claude', 'settings.json'));
    expect(claudeCode!.servers).toHaveLength(2);
  });

  it('finds Claude Code settings.local.json config', () => {
    writeConfig(dir, '.claude/settings.local.json', makeMcpServers());

    const results = discoverMcpConfigs(dir);

    const claudeCode = results.find(r => r.client === 'claude-code');
    expect(claudeCode).toBeDefined();
    expect(claudeCode!.filePath).toBe(path.join(dir, '.claude', 'settings.local.json'));
  });

  it('finds VS Code config', () => {
    writeConfig(dir, '.vscode/mcp.json', makeMcpServers());

    const results = discoverMcpConfigs(dir);

    const vscode = results.find(r => r.client === 'vscode');
    expect(vscode).toBeDefined();
    expect(vscode!.filePath).toBe(path.join(dir, '.vscode', 'mcp.json'));
    expect(vscode!.servers).toHaveLength(2);
  });

  it('finds Windsurf config', () => {
    writeConfig(dir, '.windsurf/mcp.json', makeMcpServers());

    const results = discoverMcpConfigs(dir);

    const windsurf = results.find(r => r.client === 'windsurf');
    expect(windsurf).toBeDefined();
    expect(windsurf!.filePath).toBe(path.join(dir, '.windsurf', 'mcp.json'));
    expect(windsurf!.servers).toHaveLength(2);
  });

  it('finds multiple clients simultaneously', () => {
    writeConfig(dir, '.cursor/mcp.json', makeMcpServers());
    writeConfig(dir, '.claude/settings.json', makeMcpServers());
    writeConfig(dir, '.windsurf/mcp.json', makeMcpServers());

    const results = discoverMcpConfigs(dir);

    const clients = results.map(r => r.client);
    expect(clients).toContain('cursor');
    expect(clients).toContain('claude-code');
    expect(clients).toContain('windsurf');
    expect(results).toHaveLength(3);
  });

  it('returns empty array when no configs exist', () => {
    const results = discoverMcpConfigs(dir);
    expect(results).toEqual([]);
  });

  it('skips malformed JSON files', () => {
    const configPath = path.join(dir, '.cursor', 'mcp.json');
    fs.mkdirSync(path.dirname(configPath), { recursive: true });
    fs.writeFileSync(configPath, '{ this is not valid JSON!!!');

    const results = discoverMcpConfigs(dir);
    expect(results).toEqual([]);
  });

  it('skips configs with no mcpServers key', () => {
    writeConfig(dir, '.cursor/mcp.json', { someOtherKey: 'value' });

    const results = discoverMcpConfigs(dir);
    expect(results).toEqual([]);
  });

  it('detects already-protected servers (command is secretless-mcp)', () => {
    writeConfig(dir, '.cursor/mcp.json', makeMcpServers());

    const results = discoverMcpConfigs(dir);
    const cursor = results.find(r => r.client === 'cursor')!;

    const protectedServer = cursor.servers.find(s => s.name === 'protected-server');
    expect(protectedServer).toBeDefined();
    expect(protectedServer!.alreadyProtected).toBe(true);
    expect(protectedServer!.command).toBe('secretless-mcp');

    const unprotectedServer = cursor.servers.find(s => s.name === 'my-server');
    expect(unprotectedServer).toBeDefined();
    expect(unprotectedServer!.alreadyProtected).toBe(false);
  });

  it('detects protected servers with full path to secretless-mcp', () => {
    writeConfig(dir, '.cursor/mcp.json', {
      mcpServers: {
        'path-protected': {
          command: '/usr/local/bin/secretless-mcp',
          args: ['--', 'npx', 'some-server'],
          env: {},
        },
      },
    });

    const results = discoverMcpConfigs(dir);
    const cursor = results.find(r => r.client === 'cursor')!;
    const server = cursor.servers.find(s => s.name === 'path-protected');
    expect(server).toBeDefined();
    expect(server!.alreadyProtected).toBe(true);
  });

  it('handles servers with missing optional fields gracefully', () => {
    writeConfig(dir, '.cursor/mcp.json', {
      mcpServers: {
        'minimal-server': {
          command: 'node',
        },
      },
    });

    const results = discoverMcpConfigs(dir);
    const cursor = results.find(r => r.client === 'cursor')!;
    const server = cursor.servers.find(s => s.name === 'minimal-server');
    expect(server).toBeDefined();
    expect(server!.command).toBe('node');
    expect(server!.args).toEqual([]);
    expect(server!.env).toEqual({});
    expect(server!.alreadyProtected).toBe(false);
  });

  it('preserves raw JSON for later rewriting', () => {
    const config = makeMcpServers();
    writeConfig(dir, '.cursor/mcp.json', config);

    const results = discoverMcpConfigs(dir);
    const cursor = results.find(r => r.client === 'cursor')!;
    expect(cursor.raw).toBeDefined();
    expect(cursor.raw['mcpServers']).toBeDefined();
  });

  it('handles hyphenated mcp-servers key', () => {
    writeConfig(dir, '.cursor/mcp.json', {
      'mcp-servers': {
        'hyphen-server': {
          command: 'node',
          args: ['server.js'],
          env: {},
        },
      },
    });

    const results = discoverMcpConfigs(dir);
    const cursor = results.find(r => r.client === 'cursor')!;
    expect(cursor.servers).toHaveLength(1);
    expect(cursor.servers[0].name).toBe('hyphen-server');
  });

  it('finds Claude Desktop config on Linux path', () => {
    // Linux path: .config/Claude/claude_desktop_config.json
    const configPath = path.join('.config', 'Claude', 'claude_desktop_config.json');
    writeConfig(dir, configPath, makeMcpServers());

    const results = discoverMcpConfigs(dir);

    const claudeDesktop = results.find(r => r.client === 'claude-desktop');
    expect(claudeDesktop).toBeDefined();
    expect(claudeDesktop!.filePath).toBe(path.join(dir, configPath));
  });
});

describe('discoverMcpConfigsDetailed — configs that could not be parsed', () => {
  let home: string;
  let project: string;

  beforeEach(() => { home = tmpDir(); project = tmpDir(); });
  afterEach(() => { cleanup(home); cleanup(project); });

  // Stands in for a plaintext secret value in the file.
  const marker = 'PLAINTEXT-MARKER-0123456789';

  function writeRaw(relativePath: string, content: string): string {
    const fullPath = path.join(home, relativePath);
    fs.mkdirSync(path.dirname(fullPath), { recursive: true });
    fs.writeFileSync(fullPath, content);
    return fullPath;
  }

  it('reports a config with invalid JSON by client, path and position, never quoting its content', () => {
    const configPath = writeRaw(
      '.cursor/mcp.json',
      `{\n  "mcpServers": {\n    "gh": { "command": "npx", "env": { "GITHUB_TOKEN": "${marker}" } },\n  }\n}\n`,
    );

    const { configs, unparsed } = discoverMcpConfigsDetailed(home, project);
    expect(configs).toEqual([]);
    expect(unparsed).toEqual([
      { client: 'cursor', filePath: configPath, reason: 'not valid JSON (line 4, column 3)' },
    ]);
  });

  it('never quotes the content even when the engine message would', () => {
    // JSON.parse's message for this input quotes the text around the error.
    const content = `{"mcpServers": ${marker}}`;
    writeRaw('.cursor/mcp.json', content);
    expect(() => JSON.parse(content)).toThrow(/PLAINTEXT/);

    const { unparsed } = discoverMcpConfigsDetailed(home, project);
    expect(unparsed.length).toBe(1);
    expect(unparsed[0].reason).toMatch(/^not valid JSON/);
    expect(unparsed[0].reason).not.toContain('PLAINTEXT');
  });

  it('reports a config path it could not read', () => {
    const configPath = path.join(home, '.vscode', 'mcp.json');
    fs.mkdirSync(configPath, { recursive: true });

    const { unparsed } = discoverMcpConfigsDetailed(home, project);
    expect(unparsed).toEqual([
      { client: 'vscode', filePath: configPath, reason: 'could not be read (EISDIR)' },
    ]);
  });

  it('reports a config whose top level is not a JSON object, and discoverMcpConfigs no longer throws on it', () => {
    const configPath = writeRaw('.windsurf/mcp.json', 'null');

    expect(discoverMcpConfigs(home, project)).toEqual([]);
    const { unparsed } = discoverMcpConfigsDetailed(home, project);
    expect(unparsed).toEqual([
      { client: 'windsurf', filePath: configPath, reason: 'not a JSON object' },
    ]);
  });

  it('reports a config whose server list is not an object', () => {
    const configPath = writeRaw('.cursor/mcp.json', JSON.stringify({ mcpServers: 'gh' }));

    const { unparsed } = discoverMcpConfigsDetailed(home, project);
    expect(unparsed).toEqual([
      { client: 'cursor', filePath: configPath, reason: 'its MCP server list is not a JSON object' },
    ]);
  });

  it('reports the project-scope .mcp.json too', () => {
    const configPath = path.join(project, '.mcp.json');
    fs.writeFileSync(configPath, '{ "mcpServers": ');

    const { unparsed } = discoverMcpConfigsDetailed(home, project);
    expect(unparsed.map((u) => [u.client, u.filePath])).toEqual([['claude-code', configPath]]);
  });

  it('does not report empty files, configs without servers, or parsed configs', () => {
    writeRaw('.cursor/mcp.json', '  \n');
    writeConfig(home, '.claude/settings.json', { permissions: {} });
    writeConfig(home, '.vscode/mcp.json', makeMcpServers());

    const { configs, unparsed } = discoverMcpConfigsDetailed(home, project);
    expect(unparsed).toEqual([]);
    expect(configs.map((c) => c.client)).toEqual(['vscode']);
  });
});

describe('discoverMcpConfigsDetailed — server entries with a part that could not be read', () => {
  let home: string;
  let project: string;

  beforeEach(() => { home = tmpDir(); project = tmpDir(); });
  afterEach(() => { cleanup(home); cleanup(project); });

  // Stands in for a plaintext secret value in the file.
  const marker = 'PLAINTEXT-MARKER-0123456789';

  function uncheckedIn(mcpServers: Record<string, unknown>) {
    writeConfig(home, '.cursor/mcp.json', { mcpServers });
    const { configs, unparsed } = discoverMcpConfigsDetailed(home, project);
    expect(unparsed).toEqual([]);
    expect(configs.length).toBe(1);
    return configs[0];
  }

  it('reports a server whose env is not a JSON object, and still lists the server', () => {
    const config = uncheckedIn({ gh: { command: 'npx', env: marker } });

    expect(config.unchecked).toEqual([{ name: 'gh', part: 'env', reason: 'not a JSON object' }]);
    expect(config.servers.map((s) => [s.name, s.command, s.env])).toEqual([['gh', 'npx', {}]]);
  });

  it('reports an env written as an array', () => {
    const config = uncheckedIn({ gh: { command: 'npx', env: [marker] } });

    expect(config.unchecked).toEqual([{ name: 'gh', part: 'env', reason: 'not a JSON object' }]);
  });

  it('reports each env value that is not a string by its name, and keeps the values that are', () => {
    const config = uncheckedIn({
      one: { command: 'npx', env: { API_TOKEN: 1234, GITHUB_ORG: 'my-org' } },
      two: { command: 'npx', env: { API_TOKEN: [marker], FLAGS: { token: marker } } },
    });

    expect(config.unchecked).toEqual([
      { name: 'one', part: 'env value API_TOKEN', reason: 'not a string' },
      { name: 'two', part: 'env values API_TOKEN, FLAGS', reason: 'not strings' },
    ]);
    expect(config.servers.map((s) => s.env)).toEqual([{ GITHUB_ORG: 'my-org' }, {}]);
  });

  it('reports a server entry that is not a JSON object', () => {
    const config = uncheckedIn({ gh: marker, db: [marker], fs: { command: 'npx' } });

    expect(config.unchecked).toEqual([
      { name: 'gh', part: 'entry', reason: 'not a JSON object' },
      { name: 'db', part: 'entry', reason: 'not a JSON object' },
    ]);
    expect(config.servers.map((s) => s.name)).toContain('fs');
  });

  it('never quotes a value, and writes a control character in an env name as an escape', () => {
    const config = uncheckedIn({ gh: { command: 'npx', env: { 'X\x1b[2J_TOKEN': [marker] } } });

    expect(config.unchecked).toEqual([
      { name: 'gh', part: 'env value "X\\u001b[2J_TOKEN"', reason: 'not a string' },
    ]);
    expect(JSON.stringify(config.unchecked)).not.toContain('PLAINTEXT');
  });

  it('CONTROL: reports nothing for well-formed entries, a null entry, a null env or a null env value', () => {
    const config = uncheckedIn({
      ...(makeMcpServers().mcpServers as Record<string, unknown>),
      absent: null,
      'no-env': { command: 'npx', env: null },
      'null-value': { command: 'npx', env: { GITHUB_ORG: null } },
    });

    expect(config.unchecked).toEqual([]);
  });
});

describe('discoverMcpConfigs — project-scope .mcp.json (release-test P1)', () => {
  let home: string;
  let project: string;

  beforeEach(() => { home = tmpDir(); project = tmpDir(); });
  afterEach(() => { cleanup(home); cleanup(project); });

  it('discovers project-scope .mcp.json as a claude-code config', () => {
    writeConfig(project, '.mcp.json', makeMcpServers());
    const results = discoverMcpConfigs(home, project);
    const entry = results.find(r => r.filePath === path.join(project, '.mcp.json'));
    expect(entry).toBeDefined();
    expect(entry!.client).toBe('claude-code');
    expect(entry!.servers.length).toBe(2);
  });

  it('does not invent a project entry when .mcp.json is absent', () => {
    const results = discoverMcpConfigs(home, project);
    expect(results.filter(r => r.filePath.startsWith(project)).length).toBe(0);
  });
});

describe('discoverMcpConfigsDetailed — project-level client configs', () => {
  let home: string;
  let project: string;

  beforeEach(() => { home = tmpDir(); project = tmpDir(); });
  afterEach(() => { cleanup(home); cleanup(project); });

  // A Slack-shaped bot token, built at runtime so the file holds no token literal.
  const slackToken = ['xox', 'b-1234567890-1234567890-', 'FAKEabcdefghijklmnopqrst'].join('');
  const slackServer = () => ({ command: 'npx', args: ['-y', 'slack-mcp'], env: { SLACK_BOT_TOKEN: slackToken } });

  it('finds .cursor/mcp.json in the project with an empty home, as a cursor config', () => {
    writeConfig(project, '.cursor/mcp.json', { mcpServers: { slack: slackServer() } });

    const { configs, unparsed } = discoverMcpConfigsDetailed(home, project);

    expect(unparsed).toEqual([]);
    expect(configs.map((c) => [c.client, c.filePath, c.projectPath])).toEqual([
      ['cursor', path.join(project, '.cursor', 'mcp.json'), path.join('.cursor', 'mcp.json')],
    ]);
    expect(configs[0].servers.map((s) => [s.name, s.env])).toEqual([['slack', { SLACK_BOT_TOKEN: slackToken }]]);
  });

  it('finds .vscode/mcp.json in the project, reading the servers key the VS Code workspace file carries', () => {
    writeConfig(project, '.vscode/mcp.json', { servers: { slack: { type: 'stdio', ...slackServer() } } });

    const { configs, unparsed } = discoverMcpConfigsDetailed(home, project);

    expect(unparsed).toEqual([]);
    expect(configs.map((c) => [c.client, c.filePath, c.projectPath])).toEqual([
      ['vscode', path.join(project, '.vscode', 'mcp.json'), path.join('.vscode', 'mcp.json')],
    ]);
    expect(configs[0].servers.map((s) => [s.name, s.env])).toEqual([['slack', { SLACK_BOT_TOKEN: slackToken }]]);
  });

  it('finds .windsurf/mcp.json and a bare mcp.json in the project, naming no client for the bare file', () => {
    writeConfig(project, '.windsurf/mcp.json', { mcpServers: { slack: slackServer() } });
    writeConfig(project, 'mcp.json', { mcpServers: { slack: slackServer() } });

    const { configs } = discoverMcpConfigsDetailed(home, project);

    expect(configs.map((c) => [c.client, c.projectPath])).toEqual([
      ['windsurf', path.join('.windsurf', 'mcp.json')],
      ['unknown', 'mcp.json'],
    ]);
  });

  it('reports a project-level config it could not parse, with its path from the project', () => {
    const configPath = path.join(project, '.vscode', 'mcp.json');
    fs.mkdirSync(path.dirname(configPath), { recursive: true });
    fs.writeFileSync(configPath, '{\n  "servers": {\n    "gh": { "command": "npx" },\n  }\n}\n');

    const { configs, unparsed } = discoverMcpConfigsDetailed(home, project);

    expect(configs).toEqual([]);
    expect(unparsed.map((u) => [u.client, u.filePath, u.projectPath, u.reason])).toEqual([
      ['vscode', configPath, path.join('.vscode', 'mcp.json'), 'not valid JSON (line 4, column 3)'],
    ]);
  });

  it('gives a home config no project path, beside the same file in the project', () => {
    writeConfig(home, '.cursor/mcp.json', { mcpServers: { slack: slackServer() } });
    writeConfig(project, '.cursor/mcp.json', { mcpServers: { slack: slackServer() } });

    const { configs } = discoverMcpConfigsDetailed(home, project);

    expect(configs.map((c) => [c.filePath, c.projectPath])).toEqual([
      [path.join(home, '.cursor', 'mcp.json'), undefined],
      [path.join(project, '.cursor', 'mcp.json'), path.join('.cursor', 'mcp.json')],
    ]);
  });

  it('reads each file once, as a home config, when the project directory is the home directory', () => {
    writeConfig(home, '.cursor/mcp.json', { mcpServers: { slack: slackServer() } });
    writeConfig(home, '.vscode/mcp.json', { servers: { slack: slackServer() } });

    const { configs } = discoverMcpConfigsDetailed(home, home);

    expect(configs.map((c) => [c.client, c.filePath, c.projectPath])).toEqual([
      ['cursor', path.join(home, '.cursor', 'mcp.json'), undefined],
      ['vscode', path.join(home, '.vscode', 'mcp.json'), undefined],
    ]);
  });

  it('reads a file once when the project directory reaches the home directory through a symlink', () => {
    writeConfig(home, '.cursor/mcp.json', { mcpServers: { slack: slackServer() } });
    const link = path.join(project, 'home-link');
    fs.symlinkSync(home, link);

    const { configs } = discoverMcpConfigsDetailed(home, link);

    expect(configs.map((c) => [c.client, c.filePath, c.projectPath])).toEqual([
      ['cursor', path.join(home, '.cursor', 'mcp.json'), undefined],
    ]);
  });

  it('looks in each project-level MCP config the scanner reads, and the scanner reads each one it looks in', () => {
    const projectPaths = mcpConfigLocations()
      .filter((l) => l.scope === 'project')
      .map((l) => l.relativePath.split(path.sep).join('/'));
    const scannerMcpConfigs = CONFIG_FILES.filter((f) => /(^|\/)\.?mcp\.json$/.test(f));

    expect([...projectPaths].sort()).toEqual([...scannerMcpConfigs].sort());
    expect([...projectPaths].sort()).toEqual(['.cursor/mcp.json', '.mcp.json', '.vscode/mcp.json', '.windsurf/mcp.json', 'mcp.json']);
  });

  it('gives every location a scope and the client it is read as', () => {
    const locations = mcpConfigLocations().map((l) => [l.scope, l.client, l.relativePath]);

    expect(locations).toContainEqual(['home', 'cursor', path.join('.cursor', 'mcp.json')]);
    expect(locations).toContainEqual(['project', 'claude-code', '.mcp.json']);
    expect(locations).toContainEqual(['project', 'cursor', path.join('.cursor', 'mcp.json')]);
    expect(locations).toContainEqual(['project', 'vscode', path.join('.vscode', 'mcp.json')]);
    expect(locations).toContainEqual(['project', 'windsurf', path.join('.windsurf', 'mcp.json')]);
    expect(locations).toContainEqual(['project', 'unknown', 'mcp.json']);
  });
});
