import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { discoverMcpConfigsDetailed, runsThroughSecretlessWrapper, thisBuildWrapperPath } from './discover';
import { rewriteConfig } from './rewrite';
import { protectMcp } from './protect';
import { McpVault } from './vault';

/**
 * Which entries run through a secretless wrapper, decided by one function
 * that discovery and protect-mcp's rewrite both call, and protect-mcp's
 * re-point of an entry that names another build's wrapper to the wrapper of
 * the build that runs it.
 *
 * The wrapper and the CLI run from the build (`dist/`), started in the
 * directory a client starts them in. A scratch build is a directory with a
 * `package.json` named `secretless-ai` and a `dist/mcp-wrapper.js`. Values are
 * assembled at run time and are not credentials.
 */

const CLI_PATH = path.resolve(__dirname, '..', '..', 'dist', 'cli.js');
const WRAPPER_JS = path.resolve(__dirname, '..', '..', 'dist', 'mcp-wrapper.js');
const THIS_VERSION: string = JSON.parse(fs.readFileSync(path.resolve(__dirname, '..', '..', 'package.json'), 'utf-8')).version;
const NAME = ['MY', 'SERVICE', 'API', 'KEY'].join('_');
const VALUE = ['stand', 'in', 'value', String(process.pid)].join('-');
const ID = /^[0-9a-f]{32}$/;
const REPOINTED = (server: string) => `    ~ ${server}: now runs through this version's wrapper\n`;
const REPOINTED_COUNT = (count: number) => `  ${count} server(s) now run through this version's wrapper.\n`;

let home: string;
let project: string;
let scratch: string;
let bin: string;
let saved: Record<'HOME' | 'USER' | 'PATH', string | undefined>;

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-repoint-home-'));
  project = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-repoint-proj-'));
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-repoint-dirs-'));
  bin = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-repoint-bin-'));
  // Never run: a keychain backend is not built where `local` is configured.
  fs.writeFileSync(path.join(bin, 'secret-tool'), '#!/bin/sh\nexit 1\n', { mode: 0o755 });
  // The local store's key is made from HOME and USER: this process and the
  // commands it starts get the same ones.
  saved = { HOME: process.env.HOME, USER: process.env.USER, PATH: process.env.PATH };
  process.env.HOME = home;
  delete process.env.USER;
  process.env.PATH = `${bin}${path.delimiter}${saved.PATH ?? ''}`;
  write(path.join(home, '.secretless-ai', 'config.json'), { backend: 'local' });
});

afterEach(() => {
  for (const [name, value] of Object.entries(saved)) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
  for (const d of [home, project, scratch, bin]) fs.rmSync(d, { recursive: true, force: true });
});

function write(fullPath: string, content: unknown): string {
  fs.mkdirSync(path.dirname(fullPath), { recursive: true });
  fs.writeFileSync(fullPath, typeof content === 'string' ? content : JSON.stringify(content, null, 2));
  return fullPath;
}

/** A directory under the scratch directory, made when absent. */
function dir(...parts: string[]): string {
  const full = path.join(scratch, ...parts);
  fs.mkdirSync(full, { recursive: true });
  return full;
}

const store = () => new McpVault({ storeDir: path.join(home, '.secretless-ai', 'mcp-vault'), backendType: 'local' });

function childEnv(): NodeJS.ProcessEnv {
  return { PATH: process.env.PATH, HOME: home, SECRETLESS_OS_KEYCHAIN: 'off', OPENA2A_TELEMETRY: 'off' };
}

/** Every output a cell captured, for the cell that checks no output carries a binding id. */
const captured: Array<{ cell: string; text: string; ids: string[] }> = [];

/** A command of the built CLI run in `cwd`; its output is kept. */
function runCliIn(cell: string, cwd: string, args: string[]): string {
  const res = spawnSync(process.execPath, [CLI_PATH, ...args], { cwd, encoding: 'utf-8', env: childEnv() });
  captured.push({ cell, text: `${res.stdout}${res.stderr}`, ids: [] });
  expect(res.status, `${args.join(' ')}: ${res.stderr}`).toBe(0);
  return res.stdout;
}

/** An entry started as a client starts it: its command, with its args, in `cwd`; the output is kept. */
function launch(cell: string, cwd: string, entry: { command: string; args: string[] }) {
  const res = spawnSync(process.execPath, [entry.command, ...entry.args], { cwd, encoding: 'utf-8', env: childEnv() });
  captured.push({ cell, text: `${res.stdout}${res.stderr}`, ids: [] });
  return res;
}

/** A stub server: writes its env to `sentinel`, so a test sees it started. */
function stubArgs(sentinel: string): string[] {
  return ['-e', `require('fs').writeFileSync(${JSON.stringify(sentinel)}, JSON.stringify(process.env))`];
}

/** An entry that runs through the wrapper `command` as an earlier version wrote it: no --binding. */
function wrappedOn(command: string, client: string, server: string, sentinel: string) {
  return { command, args: ['--server', server, '--client', client, '--', process.execPath, ...stubArgs(sentinel)], env: {} };
}

/** An entry with its secret in its env, not yet protected, that starts the stub. */
const plain = (sentinel: string) => ({ command: process.execPath, args: stubArgs(sentinel), env: { [NAME]: VALUE } });

/** The names an earlier version stored for a pair: values, and no binding. */
async function storeEarlier(client: string, server: string): Promise<void> {
  await store().storeServerSecrets(client, server, { [NAME]: VALUE });
}

/** A scratch build of `version`: its wrapper's path. */
function scratchBuild(name: string, version: string): string {
  const root = dir(name);
  write(path.join(root, 'package.json'), { name: 'secretless-ai', version });
  return write(path.join(root, 'dist', 'mcp-wrapper.js'), '// A wrapper build that predates the binding. Never started here.\n');
}

/** A version below `v`, and one above it. */
function lowerThan(v: string): string {
  const [major, minor, patch] = v.split(/[.+-]/).slice(0, 3).map(Number);
  if (patch > 0) return `${major}.${minor}.${patch - 1}`;
  return minor > 0 ? `${major}.${minor - 1}.0` : `${major - 1}.0.0`;
}
function higherThan(v: string): string {
  const [major, minor] = v.split('.').map(Number);
  return `${major}.${minor + 1}.0`;
}

function entryOf(file: string, name: string): { command: string; args: string[]; env?: Record<string, string> } {
  return JSON.parse(fs.readFileSync(file, 'utf-8')).mcpServers[name];
}

/** The value of the --binding before an entry's `--`. */
function idOf(args: string[]): string | undefined {
  const own = args.slice(0, args.indexOf('--'));
  const at = own.indexOf('--binding');
  return at === -1 ? undefined : own[at + 1];
}

/** The run started the server: exit 0 and the sentinel written, holding the stored value. */
function expectStarted(res: ReturnType<typeof launch>, sentinel: string) {
  expect(res.status, res.stderr).toBe(0);
  expect(fs.existsSync(sentinel)).toBe(true);
  expect(JSON.parse(fs.readFileSync(sentinel, 'utf-8'))[NAME]).toBe(VALUE);
  fs.rmSync(sentinel, { force: true });
}

/** Keeps the ids a cell's configs carry, for the cell that checks no output holds one. */
function keepIds(cell: string, ...files: string[]): void {
  const ids = files.flatMap((file) =>
    Object.values(JSON.parse(fs.readFileSync(file, 'utf-8')).mcpServers as Record<string, { args: string[] }>)
      .map((entry) => idOf(entry.args))
      .filter((id): id is string => id !== undefined));
  for (const entry of captured) if (entry.cell === cell) entry.ids.push(...ids);
}

/** This build's wrapper as a module in src/mcp or dist/mcp names it. */
const THIS_BUILD = path.resolve(__dirname, '..', 'mcp-wrapper.js');

/** Each command form, by server name, and whether it runs through a secretless wrapper. */
const FORMS: Array<{ server: string; command: string; wrapped: boolean }> = [
  { server: 'bare', command: 'secretless-mcp', wrapped: true },
  { server: 'binPath', command: '/usr/local/bin/secretless-mcp', wrapped: true },
  { server: 'otherBuild', command: '/opt/secretless-ai-old/dist/mcp-wrapper.js', wrapped: true },
  { server: 'installedCopy', command: '/home/someone/.secretless-ai/bin/mcp-wrapper.js', wrapped: true },
  { server: 'thisBuild', command: THIS_BUILD, wrapped: true },
  { server: 'node', command: process.execPath, wrapped: false },
  { server: 'npx', command: 'npx', wrapped: false },
  { server: 'otherWrapper', command: '/opt/tools/mcp-wrapper.js', wrapped: false },
  { server: 'otherScript', command: '/opt/secretless-tools/server.js', wrapped: false },
  { server: 'empty', command: '', wrapped: false },
];

describe('one function decides that an entry runs through a secretless wrapper', () => {
  it('p1: it accepts the bare name, a path ending /secretless-mcp, this build\'s wrapper and any secretless mcp-wrapper.js', () => {
    expect(thisBuildWrapperPath()).toBe(THIS_BUILD);
    for (const form of FORMS) {
      expect(runsThroughSecretlessWrapper(form.command), form.server).toBe(form.wrapped);
    }
    // The wrapper a rewrite writes counts as well, wherever it is.
    expect(runsThroughSecretlessWrapper('/opt/tools/mcp-wrapper.js', '/opt/tools/mcp-wrapper.js')).toBe(true);
    expect(runsThroughSecretlessWrapper('', '')).toBe(false);
  });

  it('p2: discovery counts an entry as wrapped exactly when protect-mcp\'s rewrite leaves its command alone', () => {
    const file = write(path.join(home, '.cursor', 'mcp.json'), {
      mcpServers: Object.fromEntries(
        FORMS.map((form) => [form.server, { command: form.command, args: ['-y', 'some-mcp'], env: { [NAME]: VALUE } }]),
      ),
    });
    const before = discoverMcpConfigsDetailed(home, project).configs.find((config) => config.filePath === file);
    expect(before).toBeDefined();
    const protectedByDiscovery = Object.fromEntries(before!.servers.map((server) => [server.name, server.alreadyProtected]));

    // Every entry is handed to the rewrite with its secret, as a direct
    // caller of rewriteConfig may hand it.
    rewriteConfig(
      file,
      'cursor',
      Object.fromEntries(FORMS.map((form) => [form.server, { [NAME]: VALUE }])),
      THIS_BUILD,
      path.join(home, '.secretless-ai', 'mcp-backups'),
    );
    const after = JSON.parse(fs.readFileSync(file, 'utf-8')).mcpServers;
    for (const form of FORMS) {
      const rewritten = after[form.server].command === THIS_BUILD && after[form.server].args[0] === '--server';
      expect(protectedByDiscovery[form.server], `discovery: ${form.server}`).toBe(form.wrapped);
      expect(rewritten, `rewrite: ${form.server}`).toBe(!form.wrapped);
    }
  });
});

describe('protect-mcp re-points an entry that names another build\'s wrapper to its own', () => {
  it('rp1: a home entry on a pre-binding build is re-pointed and bound; only --binding is added to its args, and a changed child exits 1 with B2', async () => {
    const old = scratchBuild('secretless-ai-old', lowerThan(THIS_VERSION));
    const sentinel = path.join(scratch, 'rp1-started.json');
    const file = write(path.join(home, '.cursor', 'mcp.json'), { mcpServers: { github: wrappedOn(old, 'cursor', 'github', sentinel) } });
    const before = entryOf(file, 'github');
    await storeEarlier('cursor', 'github');

    const out = runCliIn('rp1', dir('work'), ['protect-mcp']);
    const after = entryOf(file, 'github');
    expect(after.command).toBe(WRAPPER_JS);
    const id = idOf(after.args);
    expect(ID.test(id ?? ''), 'the entry carries a binding id').toBe(true);
    const at = before.args.indexOf('--');
    expect(after.args).toEqual([...before.args.slice(0, at), '--binding', id, ...before.args.slice(at)]);
    expect(after.env).toEqual(before.env);
    expect(Object.keys(after)).toEqual(Object.keys(before));
    expect(out).toContain(`  cursor (${file})\n${REPOINTED('github')}`);
    expect(out).toContain(REPOINTED_COUNT(1));

    // Started as its client starts it: it starts, and with one child argument
    // changed it exits 1 with B2 and nothing is started.
    expectStarted(launch('rp1', dir('work'), after), sentinel);
    const res = launch('rp1', dir('work'), { ...after, args: [...after.args, 'extra'] });
    expect(res.status).toBe(1);
    expect(res.stderr).toContain('are not the ones its stored secrets were bound to, so no secret was read. The server was not started.');
    expect(fs.existsSync(sentinel)).toBe(false);
    keepIds('rp1', file);
  });

  it('rp2: a .mcp.json entry on the old build that protect-mcp leaves unbound is re-pointed, and it exits 1', async () => {
    const old = scratchBuild('secretless-ai-old', lowerThan(THIS_VERSION));
    const p = dir('p');
    const sentinel = path.join(scratch, 'rp2-started.json');
    const file = write(path.join(p, '.mcp.json'), { mcpServers: { github: wrappedOn(old, 'claude-code', 'github', sentinel) } });
    const before = entryOf(file, 'github');
    // Names stored from elsewhere: protect-mcp's backup of this file does not
    // hold them, so the entry is left unbound.
    await storeEarlier('claude-code', 'github');

    const out = runCliIn('rp2', p, ['protect-mcp']);
    const after = entryOf(file, 'github');
    expect(after.command).toBe(WRAPPER_JS);
    expect(after.args).toEqual(before.args);
    expect(out).toContain("    ? github: not bound: the secrets stored under claude-code/github are not in protect-mcp's backup of this file");
    expect(out).toContain(REPOINTED('github'));
    const res = launch('rp2', p, after);
    expect(res.status).toBe(1);
    expect(res.stderr).toContain('is not bound to its stored secrets, so no secret was read. The server was not started.');
    expect(fs.existsSync(sentinel)).toBe(false);
  });

  it('rp3: an entry whose wrapper file does not exist is re-pointed, and it starts after binding', async () => {
    const gone = path.join(scratch, 'secretless-ai-gone', 'dist', 'mcp-wrapper.js');
    const sentinel = path.join(scratch, 'rp3-started.json');
    const file = write(path.join(home, '.cursor', 'mcp.json'), { mcpServers: { github: wrappedOn(gone, 'cursor', 'github', sentinel) } });
    await storeEarlier('cursor', 'github');

    runCliIn('rp3', dir('work'), ['protect-mcp']);
    const after = entryOf(file, 'github');
    expect(after.command).toBe(WRAPPER_JS);
    expectStarted(launch('rp3', dir('work'), after), sentinel);
    keepIds('rp3', file);
  });

  it("rp4: an entry on this build's wrapper reached through a symlink is left, and nothing is written", async () => {
    const link = path.join(dir('secretless-link'), 'mcp-wrapper.js');
    fs.symlinkSync(WRAPPER_JS, link);
    const sentinel = path.join(scratch, 'rp4-started.json');
    const file = write(path.join(home, '.cursor', 'mcp.json'), { mcpServers: { github: plain(sentinel) } });
    await protectMcp({ projectDir: dir('setup'), wrapperPath: link });
    expect(entryOf(file, 'github').command).toBe(link);
    const bytes = fs.readFileSync(file);

    const out = runCliIn('rp4', dir('work'), ['protect-mcp']);
    expect(fs.readFileSync(file).equals(bytes), 'the config is byte-identical').toBe(true);
    expect(out).not.toContain('now runs through this version');
    expectStarted(launch('rp4', dir('work'), entryOf(file, 'github')), sentinel);
    keepIds('rp4', file);
  });

  it('rp5: a bare secretless-mcp entry is re-pointed', async () => {
    const sentinel = path.join(scratch, 'rp5-started.json');
    const file = write(path.join(home, '.cursor', 'mcp.json'), { mcpServers: { github: wrappedOn('secretless-mcp', 'cursor', 'github', sentinel) } });
    await storeEarlier('cursor', 'github');

    const out = runCliIn('rp5', dir('work'), ['protect-mcp']);
    expect(entryOf(file, 'github').command).toBe(WRAPPER_JS);
    expect(out).toContain(REPOINTED('github'));
    expectStarted(launch('rp5', dir('work'), entryOf(file, 'github')), sentinel);
    keepIds('rp5', file);
  });

  it('rp6: a wrapped entry in .cursor/mcp.json, a config protect-mcp does not rewrite, is left byte-identical', async () => {
    const old = scratchBuild('secretless-ai-old', lowerThan(THIS_VERSION));
    const p = dir('p');
    const file = write(path.join(p, '.cursor', 'mcp.json'), { mcpServers: { github: wrappedOn(old, 'cursor', 'github', path.join(scratch, 'rp6.json')) } });
    const bytes = fs.readFileSync(file);
    await storeEarlier('cursor', 'github');

    const out = runCliIn('rp6', p, ['protect-mcp']);
    expect(fs.readFileSync(file).equals(bytes), 'the config is byte-identical').toBe(true);
    expect(out).not.toContain('now runs through this version');
  });

  it('rp7: an entry on a build that reads a version above or equal to this one is left; one below it is re-pointed', async () => {
    const builds: Record<string, string> = {
      above: scratchBuild('secretless-ai-above', higherThan(THIS_VERSION)),
      equal: scratchBuild('secretless-ai-equal', THIS_VERSION),
      below: scratchBuild('secretless-ai-below', lowerThan(THIS_VERSION)),
    };
    const file = write(path.join(home, '.cursor', 'mcp.json'), {
      mcpServers: Object.fromEntries(
        Object.entries(builds).map(([name, wrapper]) => [name, wrappedOn(wrapper, 'cursor', name, path.join(scratch, `rp7-${name}.json`))]),
      ),
    });
    for (const name of Object.keys(builds)) await storeEarlier('cursor', name);

    const out = runCliIn('rp7', dir('work'), ['protect-mcp']);
    keepIds('rp7', file);
    expect(entryOf(file, 'above').command).toBe(builds.above);
    expect(entryOf(file, 'equal').command).toBe(builds.equal);
    expect(entryOf(file, 'below').command).toBe(WRAPPER_JS);
    // Each is bound as before: the re-point changes only the command.
    for (const name of Object.keys(builds)) expect(ID.test(idOf(entryOf(file, name).args) ?? ''), name).toBe(true);
    expect(out).toContain(REPOINTED('below'));
    expect(out).not.toContain(REPOINTED('above'));
    expect(out).not.toContain(REPOINTED('equal'));
    expect(out).toContain(REPOINTED_COUNT(1));
  });

  it('rp8: the re-pointed entries are listed after the entries bound this run and before the ones left not bound', async () => {
    const old = scratchBuild('secretless-ai-old', lowerThan(THIS_VERSION));
    const p = dir('p');
    // Re-pointed and bound: a home entry whose names an earlier version stored.
    const homeFile = write(path.join(home, '.cursor', 'mcp.json'), { mcpServers: { github: wrappedOn(old, 'cursor', 'github', path.join(scratch, 'rp8-github.json')) } });
    await storeEarlier('cursor', 'github');
    // Re-pointed and left not bound: names stored from elsewhere, which
    // protect-mcp's backup of this .mcp.json does not hold.
    const projectFile = write(path.join(p, '.mcp.json'), { mcpServers: { linear: wrappedOn(old, 'claude-code', 'linear', path.join(scratch, 'rp8-linear.json')) } });
    await storeEarlier('claude-code', 'linear');

    const out = runCliIn('rp8', p, ['protect-mcp']);
    keepIds('rp8', homeFile, projectFile);
    const bound = out.indexOf('  1 server(s) bound to their config entries.\n');
    const count = out.indexOf(REPOINTED_COUNT(2));
    const notBound = out.indexOf('    ? linear: not bound: ');
    expect(bound, 'the bound group').toBeGreaterThan(-1);
    for (const server of ['github', 'linear']) {
      const at = out.indexOf(REPOINTED(server));
      expect(at, `${server}: re-pointed after the bound group`).toBeGreaterThan(bound);
      expect(at, `${server}: re-pointed before the count`).toBeLessThan(count);
    }
    expect(notBound, 'the not-bound group after the re-pointed count').toBeGreaterThan(count);
  });

  it('no output of these cells carries a binding id', () => {
    const ids = captured.flatMap((entry) => entry.ids);
    expect(ids.length, 'the cells planted ids').toBeGreaterThan(0);
    for (const entry of captured) {
      for (const id of entry.ids) expect(entry.text.includes(id), `${entry.cell} printed a binding id`).toBe(false);
    }
  });
});
