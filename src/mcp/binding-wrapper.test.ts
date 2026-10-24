import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { execFileSync, spawnSync } from 'child_process';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { protectMcp } from './protect';
import { McpVault } from './vault';
import { VERBS } from '../argv';

/**
 * The secretless-mcp wrapper reads a pair's secrets only for the config entry
 * protect-mcp bound them to, started with the command they were bound with.
 * Every other launch exits 1 with one line that says which check refused it,
 * then the fix line, and starts nothing.
 *
 * The wrapper and the CLI run from the build (`dist/`); protect-mcp runs in
 * this process with no home directory given, as the command runs it. Values
 * are assembled at run time and are not credentials.
 */

const CLI_PATH = path.resolve(__dirname, '..', '..', 'dist', 'cli.js');
const WRAPPER_JS = path.resolve(__dirname, '..', '..', 'dist', 'mcp-wrapper.js');
const WRAPPER_PATH = '/usr/local/bin/secretless-mcp';
const NAME = ['MY', 'SERVICE', 'API', 'KEY'].join('_');
const VALUE = ['stand', 'in', 'value', String(process.pid)].join('-');
const FIX =
  "secretless-mcp: Run 'npx secretless-ai mcp-status' to see which config entries are bound, then 'npx secretless-ai protect-mcp' to bind the entries it protected.";
const NOT_STARTED = 'so no secret was read. The server was not started.';

let home: string;
let project: string;
let bin: string;
let saved: Record<'HOME' | 'USER' | 'PATH', string | undefined>;

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-binding-home-'));
  project = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-binding-proj-'));
  bin = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-binding-bin-'));
  // Never run: a keychain backend is not built where `local` is configured.
  fs.writeFileSync(path.join(bin, 'secret-tool'), '#!/bin/sh\nexit 1\n', { mode: 0o755 });
  // The local store's key is made from HOME and USER: this process and the
  // commands it starts get the same ones.
  saved = { HOME: process.env.HOME, USER: process.env.USER, PATH: process.env.PATH };
  process.env.HOME = home;
  delete process.env.USER;
  process.env.PATH = `${bin}${path.delimiter}${saved.PATH ?? ''}`;
  // As `backend set local` leaves it: `local` is the encrypted file.
  write(path.join(home, '.secretless-ai', 'config.json'), { backend: 'local' });
});

afterEach(() => {
  for (const [name, value] of Object.entries(saved)) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
  for (const dir of [home, project, bin]) fs.rmSync(dir, { recursive: true, force: true });
});

function write(fullPath: string, content: unknown): string {
  fs.mkdirSync(path.dirname(fullPath), { recursive: true });
  fs.writeFileSync(fullPath, JSON.stringify(content, null, 2));
  return fullPath;
}

function childEnv(extra: Record<string, string> = {}): NodeJS.ProcessEnv {
  return { PATH: process.env.PATH, HOME: home, SECRETLESS_OS_KEYCHAIN: 'off', OPENA2A_TELEMETRY: 'off', ...extra };
}

/** A stub server: writes its env to `sentinel`, so a test sees it started and what it was given. */
function stubArgs(sentinel: string): string[] {
  return ['-e', `require('fs').writeFileSync(${JSON.stringify(sentinel)}, JSON.stringify(process.env))`];
}

/** The built wrapper started with these args in `cwd`, as a client starts an entry in its project. */
function startWrapper(args: string[], env: Record<string, string> = {}, cwd = project) {
  return spawnSync(process.execPath, [WRAPPER_JS, ...args], { cwd, encoding: 'utf-8', env: childEnv(env) });
}

function runCli(args: string[], cwd = project): string {
  return execFileSync(process.execPath, [CLI_PATH, ...args], {
    encoding: 'utf-8',
    stdio: ['pipe', 'pipe', 'pipe'],
    cwd,
    env: childEnv(),
  });
}

const homeConfig = () => path.join(home, '.cursor', 'mcp.json');

/** The entry `name` of a config file, as the file now holds it. */
function entryOf(file: string, name: string): { command: string; args: string[]; env?: Record<string, string> } {
  return JSON.parse(fs.readFileSync(file, 'utf-8')).mcpServers[name];
}

/** The args before the wrapper's own `--`, and the command after it. */
function split(args: string[]): { own: string[]; child: string[] } {
  const at = args.indexOf('--');
  return { own: args.slice(0, at), child: args.slice(at + 1) };
}

/** `name` in the home cursor config, with a secret in its env, protected by protect-mcp. */
async function protectedEntry(name = 'github') {
  const sentinel = path.join(project, `${name}-started.json`);
  const file = write(homeConfig(), {
    mcpServers: { [name]: { command: process.execPath, args: stubArgs(sentinel), env: { [NAME]: VALUE } } },
  });
  await protectMcp({ projectDir: project, wrapperPath: WRAPPER_PATH });
  const entry = entryOf(file, name);
  const own = split(entry.args).own;
  const id = own[own.indexOf('--binding') + 1];
  return { file, entry, sentinel, id };
}

const otherId = (id: string) => {
  let next = crypto.randomBytes(16).toString('hex');
  while (next === id) next = crypto.randomBytes(16).toString('hex');
  return next;
};

describe('the wrapper starts a server only from the entry protect-mcp bound its secrets to', () => {
  it('w1, CONTROL: the entry protect-mcp wrote starts the server with its secret', async () => {
    const { entry, sentinel, id } = await protectedEntry();
    expect(id).toMatch(/^[0-9a-f]{32}$/);

    const res = startWrapper(entry.args, entry.env);

    expect(res.status).toBe(0);
    expect(res.stderr).toBe('');
    const env = JSON.parse(fs.readFileSync(sentinel, 'utf-8')) as Record<string, string>;
    expect(env[NAME]).toBe(VALUE);
  });

  it('w2: the same pair and id with another command after -- exits 1 with the command line and starts nothing', async () => {
    const { entry, sentinel } = await protectedEntry();
    const { own } = split(entry.args);
    const other = [...own, '--', process.execPath, ...stubArgs(sentinel), 'extra'];

    const res = startWrapper(other, entry.env);

    expect(res.status).toBe(1);
    expect(res.stderr).toBe(
      `secretless-mcp: The command or arguments in the config entry for client "cursor", server "github" are not the ones its stored secrets were bound to, ${NOT_STARTED}\n${FIX}\n`,
    );
    expect(fs.existsSync(sentinel)).toBe(false);
  });

  it('w3: the same args without --binding exit 1 with the not-bound line and start nothing', async () => {
    const { entry, sentinel } = await protectedEntry();
    const { own, child } = split(entry.args);
    const at = own.indexOf('--binding');
    const unbound = [...own.slice(0, at), ...own.slice(at + 2), '--', ...child];

    const res = startWrapper(unbound, entry.env);

    expect(res.status).toBe(1);
    expect(res.stderr).toBe(
      `secretless-mcp: The config entry for client "cursor", server "github" is not bound to its stored secrets, ${NOT_STARTED}\n${FIX}\n`,
    );
    expect(fs.existsSync(sentinel)).toBe(false);
  });

  it('w4: another id exits 1 naming the bound entry by its server and file, and starts nothing', async () => {
    const { file, entry, sentinel, id } = await protectedEntry();
    const wrong = entry.args.map((arg) => (arg === id ? otherId(id) : arg));

    const res = startWrapper(wrong, entry.env);

    expect(res.status).toBe(1);
    expect(res.stderr).toBe(
      `secretless-mcp: The binding in the config entry for client "cursor", server "github" does not match the one stored for its secrets, which belongs to server "github" in ${file}, ${NOT_STARTED}\n${FIX}\n`,
    );
    expect(res.stderr).not.toContain(id);
    expect(fs.existsSync(sentinel)).toBe(false);
  });

  it('w5: a pair with values and no binding exits 1 naming the store and the stored pairs; mcp-status names the same store', async () => {
    // A store written by hand: the values, and no binding.
    const vaultDir = path.join(home, '.secretless-ai', 'mcp-vault');
    await new McpVault({ storeDir: vaultDir, backendType: 'local' }).storeServerSecrets('cursor', 'github', { [NAME]: VALUE });
    const sentinel = path.join(project, 'started.json');
    const args = ['--server', 'github', '--client', 'cursor', '--binding', otherId(''), '--', process.execPath, ...stubArgs(sentinel)];

    const res = startWrapper(args);

    expect(res.status).toBe(1);
    expect(res.stderr).toBe(
      `secretless-mcp: No binding for client "cursor", server "github" is stored in the local backend, ${NOT_STARTED}\n`
        + 'secretless-mcp: Stored client/server pairs: cursor/github\n'
        + `${FIX}\n`,
    );
    expect(fs.existsSync(sentinel)).toBe(false);
    // The store word in the refusal and on mcp-status's Backend line is one word.
    const refused = /stored in the (\S+) backend/.exec(res.stderr)?.[1];
    const backend = /^ {2}Backend: (\S+)$/m.exec(runCli(['mcp-status']))?.[1];
    expect(refused).toBe('local');
    expect(backend).toBe(refused);
  });

  it('w6: the server started in w1 is given no binding key and no binding text', async () => {
    const { entry, sentinel, id } = await protectedEntry();

    const res = startWrapper(entry.args, entry.env);

    expect(res.status).toBe(0);
    const env = JSON.parse(fs.readFileSync(sentinel, 'utf-8')) as Record<string, string>;
    expect(Object.keys(env).filter((key) => /binding/i.test(key))).toEqual([]);
    for (const text of [id, 'commandDigest', 'boundAt', 'sha256:']) {
      expect(Object.values(env).filter((value) => value.includes(text))).toEqual([]);
    }
    expect(`${res.stdout}${res.stderr}`).not.toContain(id);
  });

  it('a --server value holding a line feed is refused on one line, then the fix line', () => {
    // The store's directory exists, so the wrapper reaches its binding check.
    fs.mkdirSync(path.join(home, '.secretless-ai', 'mcp-vault'), { recursive: true });
    const sentinel = path.join(project, 'started.json');
    const args = ['--server', 'git\nhub', '--client', 'cursor', '--', process.execPath, ...stubArgs(sentinel)];

    const res = startWrapper(args);

    expect(res.status).toBe(1);
    const lines = res.stderr.split('\n');
    expect(lines).toHaveLength(3);
    expect(lines[0]).toMatch(/^secretless-mcp: The config entry for client "cursor", server ".+" is not bound to its stored secrets, so no secret was read\. The server was not started\.$/);
    expect(lines[1]).toBe(FIX);
    expect(lines[2]).toBe('');
    expect(fs.existsSync(sentinel)).toBe(false);
  });
});

describe('every command a binding line names is a registered command of the same build', () => {
  it('the wrapper, protect-mcp and mcp-status name only registered commands', () => {
    const cli = fs.readFileSync(path.resolve(__dirname, '..', '..', 'dist', 'cli.js'), 'utf-8');
    const named = new Set<string>();
    for (const built of ['mcp-wrapper.js', path.join('mcp', 'protect.js'), path.join('commands', 'mcp.js')]) {
      const text = fs.readFileSync(path.resolve(__dirname, '..', '..', 'dist', built), 'utf-8');
      for (const match of text.matchAll(/npx secretless-ai ([a-z][a-z-]*)/g)) named.add(match[1]);
    }
    expect([...named].sort()).toEqual(expect.arrayContaining(['mcp-status', 'protect-mcp']));
    for (const verb of named) {
      expect(VERBS[verb], `${verb} has no registry row`).toBeDefined();
      expect(cli, `${verb} is not dispatched`).toContain(`case '${verb}':`);
    }
  });
});

describe('mcp-status and the wrapper agree, entry by entry, on whether an entry starts', () => {
  it('"does not start" is printed for an entry exactly when the wrapper exits 1 for it', async () => {
    const sentinel = (name: string) => path.join(project, `${name}-started.json`);
    const file = write(homeConfig(), {
      mcpServers: {
        alpha: { command: process.execPath, args: stubArgs(sentinel('alpha')), env: { [NAME]: VALUE } },
        beta: { command: process.execPath, args: stubArgs(sentinel('beta')), env: { [NAME]: VALUE } },
      },
    });
    await protectMcp({ projectDir: project, wrapperPath: WRAPPER_PATH });
    const config = JSON.parse(fs.readFileSync(file, 'utf-8'));
    const alpha = config.mcpServers.alpha;
    const alphaId = split(alpha.args).own[split(alpha.args).own.indexOf('--binding') + 1];
    const beta = config.mcpServers.beta;
    // beta: its command changed after it was bound. gamma: a copy of alpha.
    // delta: reads alpha's pair with another id. epsilon: never bound.
    beta.args = [...beta.args, 'extra'];
    config.mcpServers.gamma = { ...alpha };
    config.mcpServers.delta = { ...alpha, args: alpha.args.map((arg: string) => (arg === alphaId ? otherId(alphaId) : arg)) };
    config.mcpServers.epsilon = {
      command: WRAPPER_PATH,
      args: ['--server', 'epsilon', '--client', 'cursor', '--', process.execPath, ...stubArgs(sentinel('epsilon'))],
    };
    write(file, config);
    // A project-level config protect-mcp does not rewrite: zeta carries
    // alpha's binding and command, eta does not carry one.
    const { own, child } = split(alpha.args);
    const at = own.indexOf('--binding');
    write(path.join(project, '.cursor', 'mcp.json'), {
      mcpServers: {
        zeta: { ...alpha },
        eta: { command: WRAPPER_PATH, args: [...own.slice(0, at), ...own.slice(at + 2), '--', ...child] },
      },
    });

    const entries: Record<string, { args: string[]; env?: Record<string, string> }> = {
      ...JSON.parse(fs.readFileSync(file, 'utf-8')).mcpServers,
      ...JSON.parse(fs.readFileSync(path.join(project, '.cursor', 'mcp.json'), 'utf-8')).mcpServers,
    };
    // Each entry started in `cwd` against its line in mcp-status run there.
    const agree = (cwd: string, status: string, names: string[]) => {
      const exits: Record<string, number | null> = {};
      for (const name of names) {
        for (const s of ['alpha', 'beta', 'epsilon']) fs.rmSync(sentinel(s), { force: true });
        const res = startWrapper(entries[name].args, entries[name].env ?? {}, cwd);
        exits[name] = res.status;
        const line = new RegExp(`^ {4}[+?] ${name}: (.*)$`, 'm').exec(status)?.[1];
        expect(line, `${name} has a line`).toBeDefined();
        expect(/does not start/.test(line ?? ''), `${name}: "${line}" against exit ${res.status}`).toBe(res.status === 1);
        expect(fs.existsSync(sentinel('alpha')) || fs.existsSync(sentinel('beta')) || fs.existsSync(sentinel('epsilon'))).toBe(res.status === 0);
      }
      return exits;
    };

    // In the project, as a client starts them there: zeta's copy of alpha's
    // binding in the project's .cursor/mcp.json is visible, so no entry that
    // carries that binding starts.
    const status = runCli(['mcp-status']);
    expect(agree(project, status, Object.keys(entries))).toEqual({ alpha: 1, beta: 1, gamma: 1, delta: 1, epsilon: 1, zeta: 1, eta: 1 });
    const zetaFile = path.join(fs.realpathSync(project), '.cursor', 'mcp.json');
    expect(status).toContain(`    ? alpha: protected and bound, but its binding also appears in ${zetaFile}, so the wrapper does not start it\n`);
    expect(status).toContain('    ? beta: protected, but its command or arguments changed since it was bound, so the wrapper does not start it\n');
    expect(status).toContain(`    ? gamma: carries the binding of the entry for server "alpha" in ${file}, but its binding also appears in ${zetaFile}, so the wrapper does not start it\n`);
    expect(status).toContain(`    ? delta: the secrets it reads are bound to the entry for server "alpha" in ${file}, so the wrapper does not start it\n`);
    expect(status).toContain('    ? epsilon: protected, not bound, so the wrapper does not start it\n');
    expect(status).toContain(`    ? zeta: carries the binding of the entry for server "alpha" in ${file}, but its binding also appears in ${zetaFile}, so the wrapper does not start it\n`);
    expect(status).toContain('    ? eta: runs through the wrapper from a config protect-mcp does not rewrite, so it is never bound and the wrapper does not start it\n');
    expect(status).toContain('  3 protected server(s) are not bound, so the wrapper does not start them.\n');
    expect(status).toContain('  Run `npx secretless-ai protect-mcp` to bind the entries it protected; it names each entry it cannot bind, and why.\n');
    expect(status).toContain('  3 bound server(s) do not start from this directory; each line above says why.\n');
    expect(status).toContain(
      '  Run `npx secretless-ai protect-mcp` to replace each home binding found outside its own entry; a copy of it then no longer starts.\n',
    );
    expect(status).not.toContain('start with secrets bound to another entry');
    expect(status).toContain(
      `  1 server(s) run through the wrapper from project-level configs protect-mcp does not rewrite, so they do not start: ${path.join('.cursor', 'mcp.json')}.\n`,
    );
    expect(status).not.toContain(alphaId);

    // In a directory with no project-level config: alpha starts, and so does
    // its copy gamma in the same home config.
    const away = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-binding-away-'));
    try {
      const awayStatus = runCli(['mcp-status'], away);
      expect(agree(away, awayStatus, ['alpha', 'beta', 'gamma', 'delta', 'epsilon'])).toEqual({ alpha: 0, beta: 1, gamma: 0, delta: 1, epsilon: 1 });
      expect(awayStatus).toContain('    + alpha: protected and bound\n');
      expect(awayStatus).toContain(`    ? gamma: carries the binding of the entry for server "alpha" in ${file}, so the wrapper starts it with that entry's secrets\n`);
      expect(awayStatus).toContain('  1 server(s) start with secrets bound to another entry. Remove each one unless it should start with those secrets.\n');
      expect(awayStatus).not.toContain(alphaId);
    } finally {
      fs.rmSync(away, { recursive: true, force: true });
    }
  });
});
