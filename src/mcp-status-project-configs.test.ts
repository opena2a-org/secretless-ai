import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { execFileSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { mcpConfigLocations } from './mcp/discover';
import { builtCommand } from './mcp/printed-command.test-support';

/**
 * `mcp-status` reads the project-level MCP client configs `scan` and `verify`
 * read (`.cursor/mcp.json`, `.vscode/mcp.json` and the others), and names
 * every path it looked in when it finds none. Before, a project holding only
 * those files got "No MCP configurations found." while `scan` reported a
 * credential in the same file. Spawns the built entry point (`dist/cli.js`)
 * so the assertions are on what a user sees.
 */

const CLI_PATH = path.resolve(__dirname, '..', 'dist', 'cli.js');

// A Slack-shaped bot token, built at runtime so the file holds no token literal.
const SLACK_TOKEN = ['xox', 'b-1234567890-1234567890-', 'FAKEabcdefghijklmnopqrst'].join('');
const SLACK_SERVER = { command: 'npx', args: ['-y', 'slack-mcp'], env: { SLACK_BOT_TOKEN: SLACK_TOKEN } };

let home: string;
let project: string;

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-mcp-status-home-'));
  project = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-mcp-status-proj-'));
});

afterEach(() => {
  fs.rmSync(home, { recursive: true, force: true });
  fs.rmSync(project, { recursive: true, force: true });
});

function runCli(args: string[]): string {
  // A minimal environment: no inherited credential variables, no real HOME.
  return execFileSync(process.execPath, [CLI_PATH, ...args], {
    encoding: 'utf-8',
    stdio: ['pipe', 'pipe', 'pipe'],
    cwd: project,
    env: { PATH: process.env.PATH, HOME: home, SECRETLESS_OS_KEYCHAIN: 'off', OPENA2A_TELEMETRY: 'off' },
  });
}

function write(baseDir: string, relativePath: string, content: string): void {
  const fullPath = path.join(baseDir, relativePath);
  fs.mkdirSync(path.dirname(fullPath), { recursive: true });
  fs.writeFileSync(fullPath, content);
}

describe('mcp-status with no MCP config in the home directory or the project', () => {
  it('lists every path it looked in, home paths with ~, and ends with "No MCP configurations found."', () => {
    const out = runCli(['mcp-status']);

    expect(out).toContain('  Looked in:\n');
    expect(out).toContain(`\n    ${path.join('~', '.cursor', 'mcp.json')}\n`);
    expect(out).toContain(`\n    ${path.join('.cursor', 'mcp.json')}\n`);
    expect(out).toContain(`\n    ${path.join('.vscode', 'mcp.json')}\n`);
    // The block is generated from the discovery list, in its order.
    const looked = mcpConfigLocations().map(
      (l) => `    ${l.scope === 'home' ? path.join('~', l.relativePath) : l.relativePath}`,
    );
    expect(out).toContain(['  Looked in:', ...looked, '', '  No MCP configurations found.'].join('\n'));
    expect(out.trimEnd().endsWith('  No MCP configurations found.')).toBe(true);
  });
});

describe('mcp-status over project-level MCP client configs', () => {
  it('lists .cursor/mcp.json and .vscode/mcp.json by their paths from the project, with their server lines', () => {
    write(project, '.cursor/mcp.json', JSON.stringify({ mcpServers: { slack: SLACK_SERVER, fs: { command: 'npx', env: {} } } }));
    write(project, '.vscode/mcp.json', JSON.stringify({ servers: { slack: { type: 'stdio', ...SLACK_SERVER } } }));

    const out = runCli(['mcp-status']);

    expect(out).not.toContain('No MCP configurations found.');
    expect(out).toContain(
      `  cursor (${path.join('.cursor', 'mcp.json')})\n    ! slack: EXPOSED (1 plaintext secret(s))\n    * fs: clean (no secrets in env)\n`,
    );
    expect(out).toContain(`  vscode (${path.join('.vscode', 'mcp.json')})\n    ! slack: EXPOSED (1 plaintext secret(s))\n`);
    expect(out).not.toContain(SLACK_TOKEN);
  });

  it('gives a runnable next step for those servers instead of sending them to protect-mcp, which leaves these files as they are', () => {
    write(project, '.cursor/mcp.json', JSON.stringify({ mcpServers: { slack: SLACK_SERVER } }));
    write(project, '.vscode/mcp.json', JSON.stringify({ servers: { slack: SLACK_SERVER } }));

    const out = runCli(['mcp-status']);

    expect(out).not.toContain(`Run \`${builtCommand('protect-mcp')}\` to encrypt exposed secrets.`);
    expect(out).toContain(
      `2 exposed server(s) are in project-level configs that protect-mcp does not rewrite: ${path.join('.cursor', 'mcp.json')}, ${path.join('.vscode', 'mcp.json')}.`,
    );
    expect(out).toContain("protect-mcp would write this machine's wrapper path into them, and these files are usually committed.");
    expect(out).toContain(`Move each value out of its file and rotate it, then run \`${builtCommand('mcp-status')}\` again.`);
  });

  it('writes a control character in a server name from a project-level config as an escape, not raw', () => {
    write(
      project,
      '.vscode/mcp.json',
      JSON.stringify({
        servers: {
          'gh\x1b[2J': SLACK_SERVER,
          'fs\x1b[2J': { command: 'npx', env: {} },
          'db\u009b2J': { command: 'secretless-mcp', args: ['--', 'npx', 'db-mcp'], env: {} },
        },
      }),
    );

    const out = runCli(['mcp-status']);

    expect(out).not.toMatch(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/);
    expect(out).toContain('    ! "gh\\u001b[2J": EXPOSED (1 plaintext secret(s))');
    expect(out).toContain('    * "fs\\u001b[2J": clean (no secrets in env)');
    // A bare secretless-mcp names no file whose version can be read, so no
    // start clause is computed for it (src/mcp/status-states.test.ts), and
    // protect-mcp does not rewrite this config.
    expect(out).toContain(
      '    ? "db\\u009b2J": protected, but it runs through a wrapper whose version could not be read; protect-mcp does not rewrite this config, so it does not re-point it\n',
    );
  });

  it('names a bare mcp.json by its path alone, as scan does', () => {
    write(project, 'mcp.json', JSON.stringify({ mcpServers: { slack: SLACK_SERVER } }));

    const out = runCli(['mcp-status']);

    expect(out).toContain('\n  mcp.json\n    ! slack: EXPOSED (1 plaintext secret(s))\n');
  });

  it('reports a project-level config it could not parse as not checked, by its path from the project', () => {
    write(project, '.vscode/mcp.json', '{\n  "servers": {\n    "gh": { "command": "npx" },\n  }\n}\n');

    const out = runCli(['mcp-status']);

    expect(out).not.toContain('No MCP configurations found.');
    expect(out).toContain(`  vscode (${path.join('.vscode', 'mcp.json')})\n    ? not checked: not valid JSON (line 4, column 3)`);
    expect(out).toContain(`Fix the file(s) above, then run \`${builtCommand('mcp-status')}\` again.`);
  });

  it('CONTROL: still sends an exposed server in the project .mcp.json to protect-mcp, which rewrites that file', () => {
    write(project, '.mcp.json', JSON.stringify({ mcpServers: { slack: SLACK_SERVER } }));

    const out = runCli(['mcp-status']);

    expect(out).toContain('  claude-code (.mcp.json)\n    ! slack: EXPOSED (1 plaintext secret(s))\n');
    expect(out).toContain(`Run \`${builtCommand('protect-mcp')}\` to encrypt exposed secrets.`);
    expect(out).not.toContain('protect-mcp does not rewrite');
  });

  it('CONTROL: still lists a home config by its full path', () => {
    write(home, '.cursor/mcp.json', JSON.stringify({ mcpServers: { slack: SLACK_SERVER } }));

    const out = runCli(['mcp-status']);

    expect(out).toContain(`  cursor (${path.join(home, '.cursor', 'mcp.json')})\n    ! slack: EXPOSED (1 plaintext secret(s))\n`);
    expect(out).toContain(`Run \`${builtCommand('protect-mcp')}\` to encrypt exposed secrets.`);
  });
});

describe('docs/use-cases/secure-mcp-configs.md', () => {
  it('names every path discovery looks in, home paths with ~', () => {
    const guide = fs.readFileSync(path.resolve(__dirname, '..', 'docs', 'use-cases', 'secure-mcp-configs.md'), 'utf-8');

    for (const location of mcpConfigLocations()) {
      const relative = location.relativePath.split(path.sep).join('/');
      expect(guide).toContain(location.scope === 'home' ? `\`~/${relative}\`` : `\`${relative}\``);
    }
  });
});

describe('mcp-unprotect over project-level MCP client configs', () => {
  it('does not list a project-level config protect-mcp leaves as it is as one it could not restore', () => {
    write(project, '.cursor/mcp.json', '{\n  "mcpServers": {\n    "gh": { "command": "npx" },\n  }\n}\n');

    const out = runCli(['mcp-unprotect']);

    expect(out).toContain('No backups found to restore.');
    expect(out).not.toContain('not restored');
  });
});
