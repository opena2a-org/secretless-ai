import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { execFileSync, spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { protectMcp } from './mcp/protect';
import { McpVault, commandDigest, newBindingId } from './mcp/vault';
import { LocalBackend } from './backends/local';
import { createBackend, effectiveBackendName } from './backends/factory';
import { runProtectMcp } from './commands/mcp';
import { sourceCommand } from './mcp/printed-command.test-support';

/**
 * #513: four follow-ups to the protect-mcp fixes of #508.
 *
 * 1. protect-mcp gave its store no key, so with no backend configured `local`
 *    was the OS keychain where one is available, while the secretless-mcp
 *    wrapper always gave its store a key and read `local` from the encrypted
 *    file. A server protect-mcp rewrote found none of its secrets at launch,
 *    and a secret in the env of a server that runs through the wrapper could
 *    not be moved into the store its wrapper reads.
 * 2. A client or server name the store refuses made protect-mcp exit 1, and
 *    the servers after it, in that file and later ones, kept their secrets.
 * 3. Each protect-mcp run that rewrote a file replaced its backup, so
 *    mcp-unprotect restored the file as the last run found it.
 * 4. For a server given --backend keychain, protect-mcp compared the backend
 *    names, `keychain` and `local`, where both build the platform keychain,
 *    and the reason it printed named a store this run does not use.
 *
 * The wrapper and the CLI run from the build (`dist/`); protect-mcp runs in
 * this process, as the command runs it: with no home directory given.
 */

// Where a case names the platform keychain (effectiveBackendName) and builds
// the run's store in its place (createBackend), it runs the same on every
// platform and stores nothing in an OS keychain. Every other call reaches the
// real function.
vi.mock('./backends/factory', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./backends/factory')>();
  return {
    ...actual,
    createBackend: vi.fn(actual.createBackend),
    effectiveBackendName: vi.fn(actual.effectiveBackendName),
  };
});

const CLI_PATH = path.resolve(__dirname, '..', 'dist', 'cli.js');
const WRAPPER_JS = path.resolve(__dirname, '..', 'dist', 'mcp-wrapper.js');
// The wrapper protect-mcp writes into a config: this build's, as the built
// CLI writes it, so its runs read these entries as on its own wrapper (an
// entry on another build's wrapper is re-pointed: binding-repoint.test.ts).
const WRAPPER_PATH = WRAPPER_JS;
const STAND_IN_KEY = 'not-a-real-key-513';

let home: string;
let project: string;
let bin: string;
let saved: Record<'HOME' | 'USER' | 'PATH', string | undefined>;

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-513-home-'));
  project = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-513-proj-'));
  bin = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-513-bin-'));
  // A Linux runner then sees a likely keychain, as macOS always does. It is
  // never run: a keychain backend reads its key index before it starts it,
  // and no case here stores anything in a keychain.
  fs.writeFileSync(path.join(bin, 'secret-tool'), '#!/bin/sh\nexit 1\n', { mode: 0o755 });
  // This process gets the home, USER and PATH the commands it starts get:
  // the local store's key is made from HOME and USER.
  saved = { HOME: process.env.HOME, USER: process.env.USER, PATH: process.env.PATH };
  process.env.HOME = home;
  delete process.env.USER;
  process.env.PATH = `${bin}${path.delimiter}${saved.PATH ?? ''}`;
});

afterEach(() => {
  vi.mocked(createBackend).mockReset();
  vi.mocked(effectiveBackendName).mockReset();
  for (const [name, value] of Object.entries(saved)) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
  for (const dir of [home, project, bin]) fs.rmSync(dir, { recursive: true, force: true });
});

function childEnv(extra: Record<string, string> = {}): NodeJS.ProcessEnv {
  return { PATH: process.env.PATH, HOME: home, SECRETLESS_OS_KEYCHAIN: 'off', OPENA2A_TELEMETRY: 'off', ...extra };
}

function runCli(args: string[]): string {
  return execFileSync(process.execPath, [CLI_PATH, ...args], {
    encoding: 'utf-8',
    stdio: ['pipe', 'pipe', 'pipe'],
    cwd: project,
    env: childEnv(),
  });
}

function write(relativePath: string, content: unknown): string {
  const fullPath = path.join(home, relativePath);
  fs.mkdirSync(path.dirname(fullPath), { recursive: true });
  fs.writeFileSync(fullPath, typeof content === 'string' ? content : JSON.stringify(content, null, 2));
  return fullPath;
}

/** As `backend set local` leaves it: `local` is the encrypted file, for protect-mcp and the wrapper alike. */
function configureLocal(): void {
  write(path.join('.secretless-ai', 'config.json'), { backend: 'local' });
}

/** A server that runs through the wrapper, with these wrapper arguments. */
const wrapped = (wrapperArgs: string[], env: Record<string, string>) => ({
  command: WRAPPER_PATH,
  args: [...wrapperArgs, '--', 'npx', 'some-mcp'],
  env,
});

/** protect-mcp as the command runs it: no home directory, its store under ~/.secretless-ai. */
const protect = (backendType?: 'local' | 'keychain') =>
  protectMcp({ projectDir: project, wrapperPath: WRAPPER_PATH, ...(backendType ? { backendType } : {}) });

/**
 * No backend configured, on a platform with a keychain: `local` without a key
 * is named as the macOS Keychain, and the store this run builds is an
 * encrypted file standing in for it.
 */
function standInKeychain(): void {
  vi.mocked(effectiveBackendName).mockImplementation((type) => (type === 'local' ? 'keychain-macos' : type));
  vi.mocked(createBackend).mockImplementation((_type, config) => new LocalBackend({ ...config, key: STAND_IN_KEY }));
}

const standInStore = () =>
  new McpVault({ backend: new LocalBackend({ storeDir: path.join(home, '.secretless-ai', 'mcp-vault'), key: STAND_IN_KEY }) });

/** runProtectMcp in this process, with what it prints to stdout and stderr. */
async function runProtect(args: string[]): Promise<{ code: number; output: string }> {
  const lines: string[] = [];
  const capture = (...parts: unknown[]) => { lines.push(parts.map(String).join(' ')); };
  const log = vi.spyOn(console, 'log').mockImplementation(capture);
  const error = vi.spyOn(console, 'error').mockImplementation(capture);
  const cwd = vi.spyOn(process, 'cwd').mockReturnValue(project);
  try {
    const code = await runProtectMcp(args);
    return { code, output: lines.join('\n') };
  } finally {
    log.mockRestore();
    error.mockRestore();
    cwd.mockRestore();
  }
}

describe('protect-mcp and the wrapper build one store for the same arguments (#513 item 1)', () => {
  it('with no backend configured, a wrapper started from the args protect-mcp writes reads the store mcp-status names', () => {
    fs.mkdirSync(path.join(home, '.secretless-ai', 'mcp-vault'), { recursive: true });
    // `Backend:` names where protect-mcp stores: with no backend configured,
    // the platform keychain, on macOS always and on Linux with secret-tool.
    const backend = /^ {2}Backend: (\S+)$/m.exec(runCli(['mcp-status']))?.[1];
    expect(backend).toBe(effectiveBackendName('local'));

    const marker = path.join(project, 'started');
    const childScript = `require('fs').writeFileSync(${JSON.stringify(marker)}, 'x')`;
    for (const backendArgs of [[], ['--backend', 'local']]) {
      const res = spawnSync(
        process.execPath,
        [WRAPPER_JS, '--server', 'github', '--client', 'cursor', ...backendArgs, '--binding', newBindingId(), '--', process.execPath, '-e', childScript],
        { encoding: 'utf-8', env: childEnv() },
      );

      // The store is empty, so the wrapper names the one it read and refuses.
      expect(res.status).toBe(1);
      expect(res.stderr).toContain(`No binding for client "cursor", server "github" is stored in the ${backend} backend, so no secret was read. The server was not started.`);
      expect(fs.existsSync(marker)).toBe(false);
    }
  });

  it('CONTROL: protect-mcp run with no home directory, and a wrapper started from the args it wrote, use one store', async () => {
    // Configured, `local` is the encrypted file for both, which this test can
    // read; with no backend configured it is the OS keychain (the case above),
    // which no test here writes to.
    configureLocal();
    const childScript = 'process.stdout.write(String(process.env.MY_SERVICE_API_KEY))';
    const cursorJson = write(path.join('.cursor', 'mcp.json'), {
      mcpServers: { github: { command: process.execPath, args: ['-e', childScript], env: { MY_SERVICE_API_KEY: 'FAKE-KEY-1234' } } },
    });

    const result = await protect();

    expect(result.servers).toEqual([{ client: 'cursor', server: 'github', secretKeys: ['MY_SERVICE_API_KEY'] }]);
    const server = JSON.parse(fs.readFileSync(cursorJson, 'utf-8')).mcpServers.github;
    expect(server.args).toEqual([
      '--server', 'github', '--client', 'cursor', '--binding', expect.stringMatching(/^[0-9a-f]{32}$/), '--', process.execPath, '-e', childScript,
    ]);
    const out = execFileSync(process.execPath, [WRAPPER_JS, ...server.args], {
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
      env: childEnv(server.env),
    });
    expect(out).toBe('FAKE-KEY-1234');
  });

  it('CONTROL: a wrapper given --vault-dir reads `local` from the encrypted file under the default key', async () => {
    // Where protect-mcp stored `local` with no backend configured before the
    // keychain upgrade (0.12.3): the encrypted file under ~/.secretless-ai/mcp-vault.
    const vaultDir = path.join(home, '.secretless-ai', 'mcp-vault');
    const store = new McpVault({ backend: new LocalBackend({ storeDir: vaultDir }) });
    await store.storeServerSecrets('cursor', 'github', { MY_SERVICE_API_KEY: 'FAKE-KEY-1234' });
    const childScript = 'process.stdout.write(String(process.env.MY_SERVICE_API_KEY))';
    // Bound as protect-mcp binds it, for the command after the wrapper's `--`.
    const id = newBindingId();
    await store.storeBinding('cursor', 'github', {
      schema: 1,
      id,
      scope: 'home',
      file: path.join(home, '.cursor', 'mcp.json'),
      client: 'cursor',
      server: 'github',
      commandDigest: commandDigest(process.execPath, ['-e', childScript]),
      boundAt: new Date().toISOString(),
      boundBy: 'test',
      boundOn: newBindingId(),
    });

    const out = execFileSync(
      process.execPath,
      [WRAPPER_JS, '--server', 'github', '--client', 'cursor', '--vault-dir', vaultDir, '--binding', id, '--', process.execPath, '-e', childScript],
      { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'], env: childEnv() },
    );

    expect(out).toBe('FAKE-KEY-1234');
  });

  it('with no backend configured, moves a secret from the env of a server that runs through the wrapper into the store its wrapper reads', async () => {
    standInKeychain();
    const cursorJson = write(path.join('.cursor', 'mcp.json'), {
      mcpServers: { github: wrapped(['--server', 'github', '--client', 'cursor'], { MY_SERVICE_API_KEY: 'FAKE-KEY-1234' }) },
    });

    for (const backendType of [undefined, 'local'] as const) {
      const result = await protect(backendType);

      expect(result.unmoved).toEqual([]);
      expect(result.servers).toEqual([{ client: 'cursor', server: 'github', secretKeys: ['MY_SERVICE_API_KEY'] }]);
      expect(JSON.parse(fs.readFileSync(cursorJson, 'utf-8')).mcpServers.github.env).toEqual({});
      expect(await standInStore().getServerSecrets('cursor', 'github')).toEqual({ MY_SERVICE_API_KEY: 'FAKE-KEY-1234' });
      // The next run starts from the same state: the pair and its binding
      // gone from the store, and the server unbound with its secret in its env.
      await standInStore().removeServerSecrets('cursor', 'github');
      write(path.join('.cursor', 'mcp.json'), {
        mcpServers: { github: wrapped(['--server', 'github', '--client', 'cursor'], { MY_SERVICE_API_KEY: 'FAKE-KEY-1234' }) },
      });
    }
  });
});

describe('protect-mcp goes on past a name the store refuses (#513 item 2)', () => {
  it('lists a server whose wrapper reads by a refused name as not moved, protects the servers after it, and exits 0', async () => {
    configureLocal();
    const dotted = wrapped(['--server', 'my.server', '--client', 'cursor'], { MY_SERVICE_API_KEY: 'FAKE-KEY-1234' });
    const cursorJson = write(path.join('.cursor', 'mcp.json'), {
      mcpServers: {
        dotted,
        github: { command: 'npx', args: ['gh-mcp'], env: { GITHUB_TOKEN: 'not-a-real-token-1' } },
      },
    });
    const settingsJson = write(path.join('.claude', 'settings.json'), {
      mcpServers: { slack: { command: 'npx', args: ['slack-mcp'], env: { SLACK_BOT_TOKEN: 'not-a-real-token-2' } } },
    });

    const { code, output } = await runProtect([]);

    expect(code).toBe(0);
    expect(output).toContain('  + cursor/github\n      GITHUB_TOKEN (encrypted)\n  + claude-code/slack\n      SLACK_BOT_TOKEN (encrypted)\n');
    expect(output).toContain('  2 secret(s) encrypted across 2 server(s).');
    expect(output).toContain([
      `  cursor (${cursorJson})`,
      '    ? dotted: secrets not moved: its wrapper reads its secrets by the server name "my.server", which the store refuses, since it holds a character other than A-Z, a-z, 0-9, - or _',
    ].join('\n'));
    expect(output).not.toContain('Error:');
    const cursor = JSON.parse(fs.readFileSync(cursorJson, 'utf-8')).mcpServers;
    expect(cursor.dotted).toEqual(dotted);
    expect(cursor.github.env).toEqual({});
    expect(JSON.parse(fs.readFileSync(settingsJson, 'utf-8')).mcpServers.slack.env).toEqual({});
  });

  it('gives the reason for an empty --server and for a --client the store refuses', async () => {
    configureLocal();
    const cases: Array<{ wrapperArgs: string[]; reason: string }> = [
      {
        wrapperArgs: ['--server', '', '--client', 'cursor'],
        reason: 'its wrapper reads its secrets by the server name "", which the store refuses, since it is empty',
      },
      {
        wrapperArgs: ['--server', 'github', '--client', 'cursor.app'],
        reason: 'its wrapper reads its secrets by the client name "cursor.app", which the store refuses, since it holds a character other than A-Z, a-z, 0-9, - or _',
      },
    ];
    for (const { wrapperArgs, reason } of cases) {
      const before = JSON.stringify({ mcpServers: { github: wrapped(wrapperArgs, { MY_SERVICE_API_KEY: 'FAKE-KEY-1234' }) } });
      const cursorJson = write(path.join('.cursor', 'mcp.json'), before);

      const result = await protect();

      expect(result.unmoved.map((server) => server.reason)).toEqual([reason]);
      expect(result.secretsFound).toBe(0);
      expect(fs.readFileSync(cursorJson, 'utf-8')).toBe(before);
    }
  });

  it('lists a server whose name the store refuses as not protected, with the reason, and protects the others', async () => {
    configureLocal();
    const refused = { command: 'npx', args: ['some-mcp'], env: { MY_SERVICE_API_KEY: 'FAKE-KEY-1234' } };
    const cursorJson = write(path.join('.cursor', 'mcp.json'), {
      mcpServers: {
        'my.server': refused,
        github: { command: 'npx', args: ['gh-mcp'], env: { GITHUB_TOKEN: 'not-a-real-token-1' } },
      },
    });

    const { code, output } = await runProtect([]);

    expect(code).toBe(0);
    expect(output).toContain('  + cursor/github\n      GITHUB_TOKEN (encrypted)\n');
    expect(output).toContain([
      `  cursor (${cursorJson})`,
      '    ? my.server: not protected: the store refuses its name, since it holds a character other than A-Z, a-z, 0-9, - or _',
      '',
      '  1 server(s) were not protected, so their secrets are still in plaintext.',
      '  The store takes only A-Z, a-z, 0-9, - and _ in a server name.',
      `  Rename each server listed above, then run \`${sourceCommand('protect-mcp')}\` again.\n`,
    ].join('\n'));
    const servers = JSON.parse(fs.readFileSync(cursorJson, 'utf-8')).mcpServers;
    expect(servers['my.server']).toEqual(refused);
    expect(servers.github.env).toEqual({});
  });
});

describe('mcp-unprotect restores the file as it was before the first protect-mcp run (#513 item 3)', () => {
  const original = JSON.stringify({
    mcpServers: { github: { command: 'npx', args: ['gh-mcp'], env: { GITHUB_TOKEN: 'not-a-real-token-1' } } },
  }, null, 2);

  type Servers = Record<string, { command: string; args: string[]; env: Record<string, string> }>;
  const changes: Array<{ label: string; change: (servers: Servers) => void }> = [
    {
      label: 'a server with a secret added since',
      change: (servers) => {
        servers.slack = { command: 'npx', args: ['slack-mcp'], env: { SLACK_BOT_TOKEN: 'not-a-real-token-2' } };
      },
    },
    {
      label: 'a secret added to the env of the server the first run wrapped',
      change: (servers) => { servers.github.env.MY_SERVICE_API_KEY = 'FAKE-KEY-1234'; },
    },
  ];

  for (const { label, change } of changes) {
    it(`after a second run that protects ${label}`, async () => {
      configureLocal();
      const cursorJson = write(path.join('.cursor', 'mcp.json'), original);
      expect((await protect()).serversProtected).toBe(1);
      const config = JSON.parse(fs.readFileSync(cursorJson, 'utf-8'));
      change(config.mcpServers);
      fs.writeFileSync(cursorJson, JSON.stringify(config, null, 2));

      expect((await protect()).serversProtected).toBe(1);
      const out = runCli(['mcp-unprotect']);

      expect(out).toContain('Restored 1 config(s) to original state.');
      expect(fs.readFileSync(cursorJson, 'utf-8')).toBe(original);
    });
  }

  it('CONTROL: once mcp-unprotect has restored the file, the next run backs it up as it is then', async () => {
    configureLocal();
    const cursorJson = write(path.join('.cursor', 'mcp.json'), original);
    await protect();
    runCli(['mcp-unprotect']);
    expect(fs.readFileSync(cursorJson, 'utf-8')).toBe(original);
    const config = JSON.parse(original);
    config.mcpServers.slack = { command: 'npx', args: ['slack-mcp'], env: { SLACK_BOT_TOKEN: 'not-a-real-token-2' } };
    const edited = JSON.stringify(config, null, 2);
    fs.writeFileSync(cursorJson, edited);

    expect((await protect()).serversProtected).toBe(2);
    runCli(['mcp-unprotect']);

    expect(fs.readFileSync(cursorJson, 'utf-8')).toBe(edited);
  });
});

describe('protect-mcp compares the stores a wrapper and this run build, and names this run\'s (#513 item 4)', () => {
  it('with no backend configured, moves a secret from the env of a server given --backend keychain into the platform keychain', async () => {
    standInKeychain();
    const cursorJson = write(path.join('.cursor', 'mcp.json'), {
      mcpServers: { github: wrapped(['--server', 'github', '--client', 'cursor', '--backend', 'keychain'], { MY_SERVICE_API_KEY: 'FAKE-KEY-1234' }) },
    });

    const result = await protect();

    expect(result.unmoved).toEqual([]);
    expect(result.secretsFound).toBe(1);
    expect(JSON.parse(fs.readFileSync(cursorJson, 'utf-8')).mcpServers.github.env).toEqual({});
    expect(await standInStore().getServerSecrets('cursor', 'github')).toEqual({ MY_SERVICE_API_KEY: 'FAKE-KEY-1234' });
  });

  it('names the store this run stores in when it leaves a secret whose wrapper reads another', async () => {
    standInKeychain();
    const before = JSON.stringify({
      mcpServers: { github: wrapped(['--server', 'github', '--client', 'cursor', '--backend', '1password'], { MY_SERVICE_API_KEY: 'FAKE-KEY-1234' }) },
    });
    const cursorJson = write(path.join('.cursor', 'mcp.json'), before);

    const result = await protect();

    expect(result.unmoved.map((server) => server.reason)).toEqual([
      'its --backend argument is "1password", and this run stores in keychain-macos',
    ]);
    expect(fs.readFileSync(cursorJson, 'utf-8')).toBe(before);
  });

  it('CONTROL: leaves the secret of a server given --backend keychain where `local` is the encrypted file, and names that store', async () => {
    vi.mocked(effectiveBackendName).mockImplementation((type) => type);
    vi.mocked(createBackend).mockImplementation((_type, config) => new LocalBackend({ ...config, key: STAND_IN_KEY }));
    const before = JSON.stringify({
      mcpServers: { github: wrapped(['--server', 'github', '--client', 'cursor', '--backend', 'keychain'], { MY_SERVICE_API_KEY: 'FAKE-KEY-1234' }) },
    });
    const cursorJson = write(path.join('.cursor', 'mcp.json'), before);

    const result = await protect();

    expect(result.unmoved.map((server) => server.reason)).toEqual([
      'its --backend argument is "keychain", and this run stores in local',
    ]);
    expect(fs.readFileSync(cursorJson, 'utf-8')).toBe(before);
  });
});
