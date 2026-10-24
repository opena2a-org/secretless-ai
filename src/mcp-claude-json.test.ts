import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { execFileSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { protectMcp } from './mcp/protect';

/**
 * Claude Code keeps its user-scope MCP servers at the top level of
 * ~/.claude.json and its local-scope servers under `projects`, keyed by the
 * project's path (#470). For a home holding servers only there, `mcp-status`
 * printed "No MCP configurations found." and `protect-mcp` left their values
 * in the file, a file `scan` reads. Spawns the built entry point
 * (`dist/cli.js`) so the assertions are on what a user sees.
 */

const CLI_PATH = path.resolve(__dirname, '..', 'dist', 'cli.js');
// The wrapper protect-mcp writes into a config: this build's, as the built
// CLI writes it, so mcp-status reads these entries as on a wrapper that checks
// its binding (an entry on another build's wrapper gets no start clause:
// src/mcp/status-states.test.ts).
const WRAPPER_PATH = path.resolve(__dirname, '..', 'dist', 'mcp-wrapper.js');

let home: string;
let project: string;
let claudeJson: string;

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-claude-json-home-'));
  project = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-claude-json-proj-'));
  claudeJson = path.join(home, '.claude.json');
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

const server = (env: Record<string, string>) => ({ type: 'stdio', command: 'npx', args: ['some-mcp'], env });

/** One user-scope server and one local-scope server, each with a value its env key marks as a secret. */
function writeClaudeJson(): string {
  const content = JSON.stringify({
    numStartups: 3,
    mcpServers: { github: server({ GITHUB_TOKEN: 'not-a-real-token-1' }) },
    projects: {
      '/work/app': { allowedTools: [], mcpServers: { slack: server({ SLACK_BOT_TOKEN: 'not-a-real-token-2' }) } },
      '/work/empty': { allowedTools: [], mcpServers: {} },
    },
  }, null, 2);
  fs.writeFileSync(claudeJson, content);
  return content;
}

/**
 * protect-mcp, run in this process with the local backend. The backup key is
 * made from HOME and USER, so they are set as the spawned CLI has them for
 * mcp-unprotect to read the backup.
 */
async function protectInProcess(): Promise<void> {
  const saved = { HOME: process.env.HOME, USER: process.env.USER };
  process.env.HOME = home;
  delete process.env.USER;
  try {
    // As the command runs it: no home directory given and the local backend
    // configured, so its store is the one mcp-status, mcp-unprotect and the
    // wrapper build from the args it writes.
    fs.mkdirSync(path.join(home, '.secretless-ai'), { recursive: true });
    fs.writeFileSync(path.join(home, '.secretless-ai', 'config.json'), JSON.stringify({ backend: 'local' }));
    await protectMcp({ projectDir: project, wrapperPath: WRAPPER_PATH });
  } finally {
    for (const [name, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
}

describe('mcp-status over ~/.claude.json', () => {
  it('lists the user-scope server at the top level and the local-scope server of a project, each under its own config', () => {
    writeClaudeJson();

    const out = runCli(['mcp-status']);

    expect(out).not.toContain('No MCP configurations found.');
    expect(out).toContain(
      [
        `  claude-code (${claudeJson})`,
        '    ! github: EXPOSED (1 plaintext secret(s))',
        '',
        `  claude-code (${claudeJson}, project /work/app)`,
        '    ! slack: EXPOSED (1 plaintext secret(s))',
        '',
      ].join('\n'),
    );
    expect(out).not.toContain('/work/empty');
    expect(out).toContain('Run `npx secretless-ai protect-mcp` to encrypt exposed secrets.');
  });

  it('names a project whose server map is not a JSON object as not checked', () => {
    fs.writeFileSync(claudeJson, JSON.stringify({ projects: { '/work/app': { mcpServers: 'not-a-map' } } }));

    const out = runCli(['mcp-status']);

    expect(out).toContain(`  claude-code (${claudeJson}, project /work/app)\n    ? not checked: its MCP server list is not a JSON object\n`);
    expect(out).not.toContain('No MCP configurations found.');
  });

  it('names ~/.claude.json in the paths it looked in when it finds no config', () => {
    const out = runCli(['mcp-status']);

    expect(out).toContain(`  Looked in:\n`);
    expect(out).toContain(`\n    ${path.join('~', '.claude.json')}\n`);
    expect(out).toContain('  No MCP configurations found.');
  });
});

describe('protect-mcp, mcp-status and mcp-unprotect over ~/.claude.json', () => {
  it('lists both servers as protected after protect-mcp, and mcp-unprotect restores the file once, as it was', async () => {
    const original = writeClaudeJson();

    await protectInProcess();
    const protectedFile = fs.readFileSync(claudeJson, 'utf-8');
    expect(protectedFile).not.toContain('not-a-real-token');

    const status = runCli(['mcp-status']);
    expect(status).toContain(`  claude-code (${claudeJson})\n    + github: protected and bound\n`);
    expect(status).toContain(`  claude-code (${claudeJson}, project /work/app)\n    + slack: protected and bound\n`);
    expect(status).not.toContain('EXPOSED');

    const unprotect = runCli(['mcp-unprotect']);
    expect(unprotect.split('\n').filter((line) => line.includes('Restored:'))).toEqual([`  + Restored: ${claudeJson}`]);
    expect(unprotect).toContain('Restored 1 config(s) to original state.');
    expect(fs.readFileSync(claudeJson, 'utf-8')).toBe(original);
  });

  it('mcp-unprotect writes back the whole file, so a change made to it after protect-mcp is undone', async () => {
    const original = writeClaudeJson();
    await protectInProcess();
    const changed = JSON.parse(fs.readFileSync(claudeJson, 'utf-8'));
    changed.projects['/work/app'].mcpServers.fs = { command: 'npx', args: ['fs-mcp'], env: {} };
    fs.writeFileSync(claudeJson, JSON.stringify(changed, null, 2));

    runCli(['mcp-unprotect']);

    expect(fs.readFileSync(claudeJson, 'utf-8')).toBe(original);
    expect(JSON.parse(fs.readFileSync(claudeJson, 'utf-8')).projects['/work/app'].mcpServers).not.toHaveProperty('fs');
  });
});

describe('protect-mcp over ~/.claude.json with several server maps (#484)', () => {
  it('prints "Scanned 1 client(s)" for a user-scope server and the local-scope servers of two projects', () => {
    fs.writeFileSync(claudeJson, JSON.stringify({
      mcpServers: { github: server({ LOG_LEVEL: 'debug' }) },
      projects: {
        '/work/app': { mcpServers: { slack: server({ LOG_LEVEL: 'debug' }) } },
        '/work/api': { mcpServers: { db: server({ LOG_LEVEL: 'debug' }) } },
      },
    }));

    const out = runCli(['protect-mcp']);

    expect(out).toContain('  Scanned 1 client(s)\n');
    expect(out).toContain('No plaintext secrets found in MCP configs. Already clean.');
  });
});
