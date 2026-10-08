import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { execFileSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

/**
 * `mcp-status`, `protect-mcp`, `mcp-unprotect` and `doctor` never print a
 * clean result over a file they could not parse or read. Spawns the built entry point (`dist/cli.js`) so the
 * assertions are on what a user sees.
 */

const CLI_PATH = path.resolve(__dirname, '..', 'dist', 'cli.js');

// Stands in for a plaintext secret value in a config file.
const MARKER = 'PLAINTEXT-MARKER-0123456789';

let home: string;
let project: string;

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-unparsed-home-'));
  project = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-unparsed-proj-'));
});

afterEach(() => {
  fs.rmSync(home, { recursive: true, force: true });
  fs.rmSync(project, { recursive: true, force: true });
});

function runCli(args: string[], extraEnv: NodeJS.ProcessEnv = {}): string {
  // A minimal environment: no inherited credential variables, no real HOME.
  return execFileSync(process.execPath, [CLI_PATH, ...args], {
    encoding: 'utf-8',
    stdio: ['pipe', 'pipe', 'pipe'],
    cwd: project,
    env: { PATH: process.env.PATH, HOME: home, SECRETLESS_OS_KEYCHAIN: 'off', ...extraEnv },
  });
}

function write(relativePath: string, content: string): string {
  const fullPath = path.join(home, relativePath);
  fs.mkdirSync(path.dirname(fullPath), { recursive: true });
  fs.writeFileSync(fullPath, content);
  return fullPath;
}

describe('mcp-status over a config it could not parse', () => {
  it('names the config as not checked instead of printing "No MCP configurations found."', () => {
    const configPath = write(
      '.cursor/mcp.json',
      `{\n  "mcpServers": {\n    "gh": { "command": "npx", "env": { "GITHUB_TOKEN": "${MARKER}" } },\n  }\n}\n`,
    );

    const out = runCli(['mcp-status']);

    expect(out).not.toContain('No MCP configurations found.');
    expect(out).toContain(`cursor (${configPath})`);
    expect(out).toContain('? not checked: not valid JSON (line 4, column 3)');
    expect(out).toContain('1 config(s) could not be parsed, so the servers in them were not checked.');
    expect(out).toContain('Fix the file(s) above, then run `npx secretless-ai mcp-status` again.');
    expect(out).not.toContain('PLAINTEXT');
  });

  it('lists the unparsed config beside the configs it did parse', () => {
    write('.vscode/mcp.json', JSON.stringify({ mcpServers: { fs: { command: 'npx', env: {} } } }));
    const unreadable = path.join(home, '.windsurf', 'mcp.json');
    fs.mkdirSync(unreadable, { recursive: true });

    const out = runCli(['mcp-status']);

    expect(out).toContain('* fs: clean (no secrets in env)');
    expect(out).toContain(`windsurf (${unreadable})`);
    expect(out).toContain('? not checked: could not be read (EISDIR)');
    expect(out).toContain('1 config(s) could not be parsed');
  });

  it('still prints "No MCP configurations found." when there is none', () => {
    const out = runCli(['mcp-status']);
    expect(out).toContain('No MCP configurations found.');
    expect(out).not.toContain('not checked');
  });
});

// A Cursor config with a trailing comma: valid but for one byte.
const TRAILING_COMMA = `{\n  "mcpServers": {\n    "gh": { "command": "npx", "env": { "GITHUB_TOKEN": "${MARKER}" } },\n  }\n}\n`;

describe('protect-mcp over a config it could not parse', () => {
  // The local backend keeps everything this command stores under the test HOME.
  const protect = () => runCli(['protect-mcp', '--backend', 'local']);

  it('names the config as not checked instead of printing "No MCP configurations found."', () => {
    const configPath = write('.cursor/mcp.json', TRAILING_COMMA);

    const out = protect();

    expect(out).not.toContain('No MCP configurations found.');
    expect(out).toContain(`cursor (${configPath})`);
    expect(out).toContain('? not checked: not valid JSON (line 4, column 3)');
    expect(out).toContain('1 config(s) could not be parsed, so the servers in them were not checked.');
    expect(out).toContain('Fix the file(s) above, then run `npx secretless-ai protect-mcp` again.');
    expect(out).not.toContain('PLAINTEXT');
    expect(fs.readFileSync(configPath, 'utf-8')).toBe(TRAILING_COMMA);
  });

  it('does not call the configs clean when one of them was not read', () => {
    write('.vscode/mcp.json', JSON.stringify({ mcpServers: { fs: { command: 'npx', env: {} } } }));
    const configPath = write('.cursor/mcp.json', TRAILING_COMMA);

    const out = protect();

    expect(out).toContain('Scanned 1 client(s)');
    expect(out).not.toContain('Already clean.');
    expect(out).toContain('No plaintext secrets found in the MCP configs that were read.');
    expect(out).toContain(`cursor (${configPath})`);
    expect(out).toContain('? not checked: not valid JSON (line 4, column 3)');
  });

  it('CONTROL: still prints "No MCP configurations found." when there is none', () => {
    const out = protect();
    expect(out).toContain('No MCP configurations found.');
    expect(out).not.toContain('not checked');
  });
});

describe('mcp-unprotect over a config it could not parse', () => {
  it('names the config as not restored instead of printing "No backups found to restore."', () => {
    const configPath = write('.cursor/mcp.json', TRAILING_COMMA);

    const out = runCli(['mcp-unprotect']);

    expect(out).not.toContain('No backups found to restore');
    expect(out).toContain(`cursor (${configPath})`);
    expect(out).toContain('? not restored: not valid JSON (line 4, column 3)');
    expect(out).toContain('1 config(s) could not be parsed, so no backup of them was restored.');
    expect(out).toContain('Fix the file(s) above, then run `npx secretless-ai mcp-unprotect` again.');
    expect(out).not.toContain('PLAINTEXT');
  });

  it('qualifies "No backups found" when it read other configs', () => {
    write('.vscode/mcp.json', JSON.stringify({ mcpServers: { fs: { command: 'npx', env: {} } } }));
    write('.cursor/mcp.json', TRAILING_COMMA);

    const out = runCli(['mcp-unprotect']);

    expect(out).toContain('No backups found to restore for the configs that were read.');
    expect(out).toContain('? not restored: not valid JSON (line 4, column 3)');
  });

  it('CONTROL: still prints "No backups found to restore." when every config was read', () => {
    write('.vscode/mcp.json', JSON.stringify({ mcpServers: { fs: { command: 'npx', env: {} } } }));

    const out = runCli(['mcp-unprotect']);

    expect(out).toContain('No backups found to restore.');
    expect(out).not.toContain('not restored');
  });
});

describe('doctor over a shell profile it could not read', () => {
  const env = { SHELL: '/bin/zsh', ANTHROPIC_API_KEY: 'set' };

  beforeEach(() => {
    write('.zshenv', 'export ANTHROPIC_API_KEY="sk-ant-..."\n');
  });

  it('marks the profile as not checked and qualifies the HEALTHY verdict', () => {
    fs.mkdirSync(path.join(home, '.zshrc'));

    const out = runCli(['doctor'], env);

    expect(out).toContain('? ~/.zshrc (interactive-only): could not be read (EISDIR), not checked');
    expect(out).not.toContain('~/.zshrc (interactive-only): no keys');
    expect(out).not.toContain('HEALTHY: All keys correctly configured');
    expect(out).toContain('HEALTHY for the profiles that were read');
    expect(out).toContain('Not checked: ~/.zshrc (EISDIR). Export lines in these files were not read.');
    expect(out).toContain('Make the file(s) readable, then run `npx secretless-ai doctor` again.');
  });

  it('prints the unqualified HEALTHY verdict when every profile was read', () => {
    write('.zshrc', '# no exports\n');

    const out = runCli(['doctor'], env);

    expect(out).toContain('+ ~/.zshrc (interactive-only): no keys');
    expect(out).toContain('HEALTHY: All keys correctly configured for subprocess access.');
    expect(out).not.toContain('Not checked');
  });
});
