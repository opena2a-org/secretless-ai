import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { execFileSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { protectMcp } from './mcp/protect';
import { builtCommand } from './mcp/printed-command.test-support';

/**
 * #508: `mcp-status` listed a server whose command is the secretless-mcp
 * wrapper as protected without classifying its env, and `protect-mcp` counted
 * it as protected and left its env as it was. The wrapper does not take a
 * value out of the file, so a plaintext secret added to the env of a wrapped
 * server stayed on disk while `mcp-status` reported the server as protected.
 * Spawns the built entry point (`dist/cli.js`) so the assertions are on what
 * a user sees. What `protect-mcp` does with such a server is checked in
 * src/mcp/protect.test.ts, and what it prints in src/commands/mcp.test.ts.
 */

const CLI_PATH = path.resolve(__dirname, '..', 'dist', 'cli.js');
const WRAPPER_JS = path.resolve(__dirname, '..', 'dist', 'mcp-wrapper.js');
// The wrapper protect-mcp writes into a config: this build's, as the built
// CLI writes it, so mcp-status reads these entries as on a wrapper that checks
// its binding (an entry on another build's wrapper gets no start clause:
// src/mcp/status-states.test.ts).
const WRAPPER_PATH = WRAPPER_JS;

let home: string;
let project: string;

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-508-home-'));
  project = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-508-proj-'));
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

function write(baseDir: string, relativePath: string, content: unknown): string {
  const fullPath = path.join(baseDir, relativePath);
  fs.mkdirSync(path.dirname(fullPath), { recursive: true });
  fs.writeFileSync(fullPath, JSON.stringify(content));
  return fullPath;
}

/** A server that runs through the wrapper, which reads its secrets as cursor/<name>. */
const wrapped = (name: string, env: Record<string, unknown>) => ({
  command: WRAPPER_PATH,
  args: ['--server', name, '--client', 'cursor', '--', 'npx', 'some-mcp'],
  env,
});

/**
 * protect-mcp in this process with the local backend, its store under
 * ~/.secretless-ai of the test's home. HOME is set as the spawned CLI has it,
 * so the configured backend is read from the same home.
 */
async function protectInProcess(): Promise<Awaited<ReturnType<typeof protectMcp>>> {
  const savedHome = process.env.HOME;
  process.env.HOME = home;
  try {
    return await protectMcp({
      homeDir: home,
      dataDir: path.join(home, '.secretless-ai'),
      projectDir: project,
      wrapperPath: WRAPPER_PATH,
      backendType: 'local',
    });
  } finally {
    if (savedHome === undefined) delete process.env.HOME;
    else process.env.HOME = savedHome;
  }
}

/**
 * protect-mcp in this process as the command runs it: no home directory given
 * and the local backend configured, so its store is the one mcp-status and the
 * wrapper build from the args it writes. USER is unset as the spawned CLI has it.
 */
async function protectAsTheCommandRunsIt(): Promise<Awaited<ReturnType<typeof protectMcp>>> {
  const saved = { HOME: process.env.HOME, USER: process.env.USER };
  process.env.HOME = home;
  delete process.env.USER;
  try {
    write(home, path.join('.secretless-ai', 'config.json'), { backend: 'local' });
    return await protectMcp({ projectDir: project, wrapperPath: WRAPPER_PATH });
  } finally {
    for (const [name, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
}

describe('mcp-status classifies the env of a server that runs through the wrapper (#508)', () => {
  it('lists a server whose command is secretless-mcp, with a key in its env, as exposed', () => {
    write(project, 'mcp.json', { mcpServers: { demo: { command: 'secretless-mcp', env: { MY_SERVICE_API_KEY: 'FAKE-KEY-1234' } } } });

    const out = runCli(['mcp-status']);

    expect(out).toContain('\n  mcp.json\n    ! demo: EXPOSED (1 plaintext secret(s))\n');
    expect(out).not.toContain('demo: protected');
    expect(out).toContain('1 exposed server(s) are in project-level configs that protect-mcp does not rewrite: mcp.json.');
  });

  it('lists a wrapped server with a secret in its env as exposed, one without as protected, and one with an env value it could not read as neither', () => {
    const cursorJson = write(home, path.join('.cursor', 'mcp.json'), {
      mcpServers: {
        exposed: wrapped('exposed', { MY_SERVICE_API_KEY: 'FAKE-KEY-1234', LOG_LEVEL: 'debug' }),
        wrapped: wrapped('wrapped', { LOG_LEVEL: 'debug' }),
        partial: wrapped('partial', { API_TOKEN: 1234 }),
      },
    });

    const out = runCli(['mcp-status']);

    expect(out).toContain([
      `  cursor (${cursorJson})`,
      '    ! exposed: EXPOSED (1 plaintext secret(s))',
      '    ? wrapped: protected, not bound, so the wrapper does not start it',
      `      \`${builtCommand('protect-mcp')}\` binds it.`,
      '    ? partial: env value API_TOKEN not checked: not a string',
      '',
    ].join('\n'));
    expect(out).not.toContain('exposed: protected');
    expect(out).not.toContain('partial: protected');
    expect(out).toContain(`Run \`${builtCommand('protect-mcp')}\` to encrypt exposed secrets.`);
  });

  it('lists the server as protected once protect-mcp has moved the secret out of its env', async () => {
    const cursorJson = write(home, path.join('.cursor', 'mcp.json'), {
      mcpServers: { github: wrapped('github', { MY_SERVICE_API_KEY: 'FAKE-KEY-1234' }) },
    });
    expect(runCli(['mcp-status'])).toContain('    ! github: EXPOSED (1 plaintext secret(s))\n');

    const result = await protectAsTheCommandRunsIt();
    expect(result.servers).toEqual([{ client: 'cursor', server: 'github', secretKeys: ['MY_SERVICE_API_KEY'] }]);
    expect(fs.readFileSync(cursorJson, 'utf-8')).not.toContain('FAKE-KEY-1234');

    const out = runCli(['mcp-status']);

    expect(out).toContain(`  cursor (${cursorJson})\n    + github: protected and bound\n`);
    expect(out).not.toContain('EXPOSED');
  });

  it('the wrapper starts the server with the value protect-mcp moved out of its env', async () => {
    const childScript = 'process.stdout.write(String(process.env.MY_SERVICE_API_KEY))';
    const cursorJson = write(home, path.join('.cursor', 'mcp.json'), {
      mcpServers: {
        github: {
          command: WRAPPER_PATH,
          args: ['--server', 'github', '--client', 'cursor', '--', process.execPath, '-e', childScript],
          env: { MY_SERVICE_API_KEY: 'FAKE-KEY-1234' },
        },
      },
    });

    await protectInProcess();
    const server = JSON.parse(fs.readFileSync(cursorJson, 'utf-8')).mcpServers.github;
    expect(server.env).toEqual({});

    // Started as a client starts it, with its args and env, given the store
    // protect-mcp wrote to in this test's home.
    const out = execFileSync(
      process.execPath,
      [
        WRAPPER_JS,
        '--vault-dir', path.join(home, '.secretless-ai', 'mcp-vault'),
        '--vault-key', `${home}-secretless-mcp-${process.env.USER ?? 'default'}`,
        ...server.args,
      ],
      {
        encoding: 'utf-8',
        stdio: ['pipe', 'pipe', 'pipe'],
        env: { PATH: process.env.PATH, HOME: home, SECRETLESS_OS_KEYCHAIN: 'off', ...server.env },
      },
    );

    expect(out).toBe('FAKE-KEY-1234');
  });
});
