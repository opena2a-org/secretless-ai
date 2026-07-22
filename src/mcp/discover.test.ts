import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { discoverMcpConfigs, McpConfigFile } from './discover';

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
