import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { protectMcp } from './protect';
import * as protectModule from './protect';
import { McpVault, commandDigest, newBindingId } from './vault';
import { rewriteConfig } from './rewrite';
import { runProtectMcp } from '../commands/mcp';

/**
 * A binding after its entry, its file or its store changed outside
 * protect-mcp. mcp-unprotect deletes a pair only where its binding names a
 * file it restored. protect-mcp binds a pair with no name stored only to the
 * values an entry brings, and binds again a .mcp.json entry whose project
 * directory moved, where this machine's backup of the old file holds the
 * stored values. No output carries a binding id.
 *
 * The wrapper and the CLI run from the build (`dist/`), started in the
 * directory a client starts them in. Values are assembled at run time and are
 * not credentials.
 */

const CLI_PATH = path.resolve(__dirname, '..', '..', 'dist', 'cli.js');
const WRAPPER_JS = path.resolve(__dirname, '..', '..', 'dist', 'mcp-wrapper.js');
const WRAPPER_PATH = '/usr/local/bin/secretless-mcp';
const NAME = ['MY', 'SERVICE', 'API', 'KEY'].join('_');
const VALUE = ['stand', 'in', 'value', String(process.pid)].join('-');
const ID = /^[0-9a-f]{32}$/;

/** Every output a cell captured, and every id a cell planted with the config text that holds it. */
const captured: Array<{ cell: string; text: string }> = [];
const planted: Array<{ cell: string; id: string; config: string }> = [];

let home: string;
let scratch: string;
let bin: string;
let saved: Record<'HOME' | 'USER' | 'PATH', string | undefined>;

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-recover-home-'));
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-recover-dirs-'));
  bin = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-recover-bin-'));
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
  for (const d of [home, scratch, bin]) {
    // A cell may leave a directory it cannot search; give it back first.
    fs.chmodSync(d, 0o700);
    fs.rmSync(d, { recursive: true, force: true });
  }
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

const real = (p: string) => fs.realpathSync(p);
const store = () => new McpVault({ storeDir: path.join(home, '.secretless-ai', 'mcp-vault'), backendType: 'local' });
const backupDir = () => path.join(home, '.secretless-ai', 'mcp-backups');

function childEnv(): NodeJS.ProcessEnv {
  return { PATH: process.env.PATH, HOME: home, SECRETLESS_OS_KEYCHAIN: 'off', OPENA2A_TELEMETRY: 'off' };
}

/** A stub server: writes its env to `sentinel`, so a test sees it started. */
function stubArgs(sentinel: string): string[] {
  return ['-e', `require('fs').writeFileSync(${JSON.stringify(sentinel)}, JSON.stringify(process.env))`];
}

/** An entry with its secret in its env, not yet protected, that starts the stub. */
const plain = (sentinel: string) => ({ command: process.execPath, args: stubArgs(sentinel), env: { [NAME]: VALUE } });

/** The built wrapper started in `cwd` with an entry's args, as a client starts it; its output is kept. */
function startIn(cell: string, cwd: string, args: string[]) {
  const res = spawnSync(process.execPath, [WRAPPER_JS, ...args], { cwd, encoding: 'utf-8', env: childEnv() });
  captured.push({ cell, text: `${res.stdout}${res.stderr}` });
  return res;
}

/** A command of the built CLI run in `cwd`; its output is kept. */
function runCliIn(cell: string, cwd: string, args: string[]): string {
  const res = spawnSync(process.execPath, [CLI_PATH, ...args], { cwd, encoding: 'utf-8', env: childEnv() });
  captured.push({ cell, text: `${res.stdout}${res.stderr}` });
  expect(res.status, `${args.join(' ')}: ${res.stderr}`).toBe(0);
  return res.stdout;
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

/** Keeps an id a cell planted, with the config text that holds it, for the last cell. */
function plant(cell: string, file: string, id: string | undefined): string {
  expect(ID.test(id ?? ''), 'the entry carries a binding id').toBe(true);
  planted.push({ cell, id: id!, config: fs.readFileSync(file, 'utf-8') });
  return id!;
}

/** `github` in the .mcp.json of project directory `name`, protected by protect-mcp: a project-level binding. */
async function projectRecord(cell: string, name = 'a') {
  const a = dir(name);
  const sentinel = path.join(scratch, `${name}-started.json`);
  const file = write(path.join(a, '.mcp.json'), { mcpServers: { github: plain(sentinel) } });
  await protectMcp({ projectDir: a, wrapperPath: WRAPPER_PATH });
  const entry = entryOf(file, 'github');
  const id = plant(cell, file, idOf(entry.args));
  return { a, file, entry, sentinel, id };
}

/** `github` in the home cursor config, protected by protect-mcp: a home binding. */
async function homeRecord(cell: string) {
  const sentinel = path.join(scratch, 'home-started.json');
  const file = write(path.join(home, '.cursor', 'mcp.json'), { mcpServers: { github: plain(sentinel) } });
  await protectMcp({ projectDir: dir('setup'), wrapperPath: WRAPPER_PATH });
  const entry = entryOf(file, 'github');
  const id = plant(cell, file, idOf(entry.args));
  return { file, entry, sentinel, id };
}

/** A server that runs through the wrapper, as an earlier version wrote it: no --binding. */
const wrappedUnbound = (client: string, server: string) => ({
  command: WRAPPER_PATH,
  args: ['--server', server, '--client', client, '--', process.execPath, '-e', 'x'],
  env: {},
});

/** Puts the values back in an entry's env, as an operator does by hand. */
function putValuesBack(file: string, name: string): void {
  const config = JSON.parse(fs.readFileSync(file, 'utf-8'));
  config.mcpServers[name].env = { ...config.mcpServers[name].env, [NAME]: VALUE };
  write(file, config);
}

/** A command of the CLI in this process, from `cwd`, with what it prints; the output is kept. */
async function run(cell: string, command: () => Promise<number>, cwd: string): Promise<string> {
  const lines: string[] = [];
  const capture = (...parts: unknown[]) => { lines.push(parts.map(String).join(' ')); };
  const log = vi.spyOn(console, 'log').mockImplementation(capture);
  const error = vi.spyOn(console, 'error').mockImplementation(capture);
  const at = vi.spyOn(process, 'cwd').mockReturnValue(cwd);
  try {
    const code = await command();
    expect(code).toBe(0);
  } finally {
    log.mockRestore();
    error.mockRestore();
    at.mockRestore();
  }
  const output = lines.join('\n');
  captured.push({ cell, text: output });
  return output;
}

/** The command after an entry's own `--`, as its digest covers it. */
function digestOf(args: string[]): string {
  const child = args.slice(args.indexOf('--') + 1);
  return commandDigest(child[0], child.slice(1));
}

/** The run started the server: exit 0 and the sentinel written, holding the stored value. */
function expectStarted(res: ReturnType<typeof startIn>, sentinel: string) {
  expect(res.status, res.stderr).toBe(0);
  expect(fs.existsSync(sentinel)).toBe(true);
  expect(JSON.parse(fs.readFileSync(sentinel, 'utf-8'))[NAME]).toBe(VALUE);
  fs.rmSync(sentinel, { force: true });
}

describe('mcp-unprotect deletes a pair only where its binding names a file it restored', () => {
  it('u2: a pair bound in project A, read by an entry of project B whose restored file holds equal values, is left; A still starts', async () => {
    const { a, entry, sentinel } = await projectRecord('u2');
    // Project B as an earlier version left it: the entry wrapped with no
    // --binding, and protect-mcp's backup of the file holding the same values,
    // under the path the CLI started in B finds it at.
    const b = real(dir('b'));
    const bFile = write(path.join(b, '.mcp.json'), { mcpServers: { github: plain(sentinel) } });
    rewriteConfig(bFile, 'claude-code', { github: { [NAME]: VALUE } }, WRAPPER_PATH, backupDir());
    const record = await store().getBinding('claude-code', 'github');

    const out = runCliIn('u2', b, ['mcp-unprotect']);

    expect(out).toContain(`  + Restored: ${bFile}\n`);
    expect(out).toContain(
      `  ? claude-code/github: left in the store; it is bound to server "github" in ${record!.file}, which this run did not restore.\n`,
    );
    expect(out).not.toContain('Deleted from the store');
    expect(await store().getServerSecrets('claude-code', 'github')).toEqual({ [NAME]: VALUE });
    expect(await store().getBinding('claude-code', 'github')).toEqual(record);
    expectStarted(startIn('u2', a, entry.args), sentinel);
  });
});

describe('a pair whose names and binding were deleted is bound again only to the values an entry brings', () => {
  const NOT_IN_BACKUP =
    "the secrets stored under claude-code/github are not in protect-mcp's backup of this file, and a project-level entry is bound only to values protect-mcp stores from its file. "
    + "If this entry is yours, put the server's values in its env, and run `npx secretless-ai protect-mcp`.";

  it('m1: a .mcp.json entry given its values again is bound with a new id, its values stored, and it starts', async () => {
    const { a, file, sentinel, id: stale } = await projectRecord('m1');
    await store().removeServerSecrets('claude-code', 'github');
    putValuesBack(file, 'github');

    const result = await protectMcp({ projectDir: a, wrapperPath: WRAPPER_PATH });

    expect(result.bound).toEqual([{ client: 'claude-code', filePath: path.join(a, '.mcp.json'), projectPath: '.mcp.json', server: 'github' }]);
    const entry = entryOf(file, 'github');
    const record = await store().getBinding('claude-code', 'github');
    expect(record).toMatchObject({ scope: 'project', file: path.join(a, '.mcp.json') });
    expect(idOf(entry.args)).toBe(record!.id);
    expect(record!.id).not.toBe(stale);
    plant('m1', file, record!.id);
    expect(entry.env ?? {}).not.toHaveProperty(NAME);
    expect(await store().getServerSecrets('claude-code', 'github')).toEqual({ [NAME]: VALUE });
    expectStarted(startIn('m1', a, entry.args), sentinel);
  });

  it('m2: a home entry given its values again is bound with a new id, its values stored, and it starts', async () => {
    const { file, sentinel, id: stale } = await homeRecord('m2');
    await store().removeServerSecrets('cursor', 'github');
    putValuesBack(file, 'github');

    const result = await protectMcp({ projectDir: dir('setup'), wrapperPath: WRAPPER_PATH });

    expect(result.bound).toEqual([{ client: 'cursor', filePath: file, server: 'github' }]);
    const entry = entryOf(file, 'github');
    const record = await store().getBinding('cursor', 'github');
    expect(record).toMatchObject({ scope: 'home', file });
    expect(idOf(entry.args)).toBe(record!.id);
    expect(record!.id).not.toBe(stale);
    plant('m2', file, record!.id);
    expect(entry.env ?? {}).not.toHaveProperty(NAME);
    expect(await store().getServerSecrets('cursor', 'github')).toEqual({ [NAME]: VALUE });
    expectStarted(startIn('m2', dir('elsewhere'), entry.args), sentinel);
  });

  it('m3: a .mcp.json entry with no value in its env is left, though the backup holds a server of its name; nothing is written', async () => {
    const { a, file } = await projectRecord('m3');
    await store().removeServerSecrets('claude-code', 'github');
    const before = fs.readFileSync(file, 'utf-8');

    const result = await protectMcp({ projectDir: a, wrapperPath: WRAPPER_PATH });

    expect(result.bound).toEqual([]);
    expect(result.unbound).toEqual([
      { client: 'claude-code', filePath: path.join(a, '.mcp.json'), projectPath: '.mcp.json', server: 'github', reason: NOT_IN_BACKUP },
    ]);
    expect(await store().getBinding('claude-code', 'github')).toBeUndefined();
    expect(fs.readFileSync(file, 'utf-8')).toBe(before);
  });

  it('m4: with a second wrapped reader of the pair in a home config, both are left with the others reason and nothing is stored', async () => {
    const { a, file } = await projectRecord('m4');
    await store().removeServerSecrets('claude-code', 'github');
    putValuesBack(file, 'github');
    const settings = write(path.join(home, '.claude', 'settings.json'), { mcpServers: { github: wrappedUnbound('claude-code', 'github') } });

    const result = await protectMcp({ projectDir: a, wrapperPath: WRAPPER_PATH });

    const others = (other: string) =>
      `claude-code/github is also read by server "github" in ${other}, and the secrets stored under a name are bound to one entry only. `
      + 'Keep one of these entries, remove the others, and run `npx secretless-ai protect-mcp`; to run another as well, add it again under a new name with its values.';
    expect(result.bound).toEqual([]);
    expect(result.unbound).toEqual(expect.arrayContaining([
      { client: 'claude-code', filePath: path.join(a, '.mcp.json'), projectPath: '.mcp.json', server: 'github', reason: others(settings) },
      { client: 'claude-code', filePath: settings, server: 'github', reason: others(path.join(a, '.mcp.json')) },
    ]));
    expect(result.unbound).toHaveLength(2);
    expect(await store().getServerSecrets('claude-code', 'github')).toEqual({});
    expect(await store().getBinding('claude-code', 'github')).toBeUndefined();
  });
});

/** `github` bound in project A, then A moved to A2: the binding names A's .mcp.json, which no longer exists. */
async function movedProject(cell: string) {
  const a = real(dir('a'));
  const sentinel = path.join(scratch, 'moved-started.json');
  const file = write(path.join(a, '.mcp.json'), { mcpServers: { github: plain(sentinel) } });
  await protectMcp({ projectDir: a, wrapperPath: WRAPPER_PATH });
  const id = plant(cell, file, idOf(entryOf(file, 'github').args));
  const a2 = path.join(path.dirname(a), 'a2');
  fs.renameSync(a, a2);
  return { a, a2, file, moved: path.join(a2, '.mcp.json'), sentinel, id };
}

describe('T7: protect-mcp binds again a .mcp.json entry whose project directory moved', () => {
  const manifestKeys = () => Object.keys(JSON.parse(fs.readFileSync(path.join(backupDir(), 'manifest.json'), 'utf-8')));

  it('T7a: started in the moved directory, it exits 1 naming the old directory, and the server does not start', async () => {
    const { a, a2, moved, sentinel } = await movedProject('T7a');

    const res = startIn('T7a', a2, entryOf(moved, 'github').args);

    expect(res.status).toBe(1);
    expect(res.stderr).toContain(`are bound to the project in ${a}, and ${a} could not be resolved (ENOENT)`);
    expect(fs.existsSync(sentinel)).toBe(false);
  });

  it('T7b: protect-mcp in the moved directory binds it again with a new id, names the old directory, and moves the backup to the new path', async () => {
    const { a, a2, file, moved, id } = await movedProject('T7b');

    const output = await run('T7b', () => runProtectMcp([]), a2);

    expect(output).toContain(`  claude-code (.mcp.json)\n    + github: bound again; its project directory moved from ${a}\n`);
    const now = idOf(entryOf(moved, 'github').args);
    plant('T7b', moved, now);
    expect(now).not.toBe(id);
    expect(await store().getBinding('claude-code', 'github')).toMatchObject({ id: now, scope: 'project', file: moved });
    expect(manifestKeys()).toContain(moved);
    expect(manifestKeys()).not.toContain(file);
  });

  it('T7c: after protect-mcp, started in the moved directory, the server starts', async () => {
    const { a2, moved, sentinel } = await movedProject('T7c');
    await run('T7c', () => runProtectMcp([]), a2);
    plant('T7c', moved, idOf(entryOf(moved, 'github').args));

    expectStarted(startIn('T7c', a2, entryOf(moved, 'github').args), sentinel);
  });

  it('T7d: mcp-unprotect in the moved directory restores the file and deletes the pair and its binding', async () => {
    const { a2, moved, sentinel } = await movedProject('T7d');
    await run('T7d', () => runProtectMcp([]), a2);

    const out = runCliIn('T7d', a2, ['mcp-unprotect']);

    expect(out).toContain(`  + Restored: ${moved}\n`);
    expect(entryOf(moved, 'github')).toEqual(plain(sentinel));
    expect(await store().getServerSecrets('claude-code', 'github')).toEqual({});
    expect(await store().getBinding('claude-code', 'github')).toBeUndefined();
  });

  it('T7e: a copy of the bound .mcp.json in another directory while the original exists is reported as a copy and not taken over', async () => {
    const a = real(dir('a'));
    const file = write(path.join(a, '.mcp.json'), { mcpServers: { github: plain(path.join(scratch, 'started.json')) } });
    await protectMcp({ projectDir: a, wrapperPath: WRAPPER_PATH });
    plant('T7e', file, idOf(entryOf(file, 'github').args));
    const b = real(dir('b'));
    const copy = path.join(b, '.mcp.json');
    fs.copyFileSync(file, copy);
    const before = fs.readFileSync(copy, 'utf-8');

    const output = await run('T7e', () => runProtectMcp([]), b);

    expect(output).toContain(
      `    ? github: a copy of a bound entry: it carries the binding of server "github" in ${file}, so the wrapper gives it that server's secrets. Remove this entry;`,
    );
    expect(output).not.toContain('bound again');
    expect((await store().getBinding('claude-code', 'github'))!.file).toBe(file);
    expect(fs.readFileSync(copy, 'utf-8')).toBe(before);
  });

  it('T7f: a binding naming a file that does not exist, with no backup of it here, is reported as a copy with the missing-file clause; nothing is written', async () => {
    const gone = path.join(real(scratch), 'gone', '.mcp.json');
    const sentinel = path.join(scratch, 'started.json');
    const child = [process.execPath, ...stubArgs(sentinel)];
    const id = newBindingId();
    await store().storeBinding('claude-code', 'github', {
      schema: 1,
      id,
      scope: 'project',
      file: gone,
      client: 'claude-code',
      server: 'github',
      commandDigest: commandDigest(child[0], child.slice(1)),
      boundAt: new Date().toISOString(),
      boundBy: 'test',
    });
    await store().storeServerSecrets('claude-code', 'github', { [NAME]: VALUE });
    const b = real(dir('b'));
    const copy = write(path.join(b, '.mcp.json'), {
      mcpServers: { github: { command: WRAPPER_PATH, args: ['--server', 'github', '--client', 'claude-code', '--binding', id, '--', ...child], env: {} } },
    });
    plant('T7f', copy, id);
    const before = fs.readFileSync(copy, 'utf-8');
    const record = await store().getBinding('claude-code', 'github');

    const output = await run('T7f', () => runProtectMcp([]), b);

    expect(output).toContain(
      `    ? github: a copy of a bound entry: it carries the binding of server "github" in ${gone}, so the wrapper gives it that server's secrets. ${gone} no longer exists. Remove this entry;`,
    );
    expect(fs.readFileSync(copy, 'utf-8')).toBe(before);
    expect(await store().getBinding('claude-code', 'github')).toEqual(record);
    expect(fs.existsSync(path.join(backupDir(), 'manifest.json'))).toBe(false);
  });

  it('T7g: a moved entry whose command changed is bound again, its line names the change, and the binding takes its command now', async () => {
    const { a, a2, moved, sentinel } = await movedProject('T7g');
    const config = JSON.parse(fs.readFileSync(moved, 'utf-8'));
    config.mcpServers.github.args = [...config.mcpServers.github.args, 'extra'];
    write(moved, config);

    const output = await run('T7g', () => runProtectMcp([]), a2);

    expect(output).toContain(
      `    + github: bound again; its project directory moved from ${a}; its command or arguments changed since it was bound\n`,
    );
    const entry = entryOf(moved, 'github');
    plant('T7g', moved, idOf(entry.args));
    expect(await store().getBinding('claude-code', 'github')).toMatchObject({ id: idOf(entry.args), file: moved, commandDigest: digestOf(entry.args) });
    expectStarted(startIn('T7g', a2, entry.args), sentinel);
  });

  it('T7h: where the store refuses the new binding, the backup stays filed under the old path, nothing is written, and the line names the error', async () => {
    const { a2, file, moved, id } = await movedProject('T7h');
    const before = fs.readFileSync(moved, 'utf-8');
    const vaultDir = path.join(home, '.secretless-ai', 'mcp-vault');
    // The local store writes through a file it creates beside its own.
    fs.chmodSync(vaultDir, 0o500);
    let output: string;
    try {
      output = await run('T7h', () => runProtectMcp([]), a2);
    } finally {
      fs.chmodSync(vaultDir, 0o700);
    }

    expect(output).toContain('    ? github: not bound: the binding could not be stored (');
    expect(output).not.toContain('bound again');
    expect(manifestKeys()).toContain(file);
    expect(manifestKeys()).not.toContain(moved);
    expect(fs.readFileSync(moved, 'utf-8')).toBe(before);
    expect(await store().getBinding('claude-code', 'github')).toMatchObject({ id, file });
  });
});

describe('X3: an entry at its binding\'s place carrying another id is bound again in a home config, and left in a .mcp.json', () => {
  /** Writes `id` as the entry's --binding, or removes the flag and its value where `id` is undefined. */
  function setId(file: string, name: string, id: string | undefined): void {
    const config = JSON.parse(fs.readFileSync(file, 'utf-8'));
    const args: string[] = config.mcpServers[name].args;
    const at = args.indexOf('--binding');
    if (id === undefined) args.splice(at, 2);
    else args[at + 1] = id;
    write(file, config);
  }

  /** The wrapper refused the entry with B1, the binding check: exit 1, nothing started. */
  function expectB1(res: ReturnType<typeof startIn>, sentinel: string, client: string) {
    expect(res.status).toBe(1);
    expect(res.stderr).toContain(`The binding in the config entry for client "${client}", server "github" does not match the one stored for its secrets`);
    expect(fs.existsSync(sentinel)).toBe(false);
  }

  const OTHER_ID_PROJECT =
    'its binding does not match the one stored for claude-code/github. '
    + 'If this entry is yours, add the server again under a new name with its values, remove this entry, and run `npx secretless-ai protect-mcp`.';

  it('X3-a and X3-f: a home entry whose id was replaced is refused with B1, then bound again with its binding\'s id; nothing else changes, and it starts', async () => {
    const { file, sentinel, id } = await homeRecord('X3-a');
    const bound = fs.readFileSync(file, 'utf-8');
    const record = await store().getBinding('cursor', 'github');
    const stale = newBindingId();
    setId(file, 'github', stale);
    plant('X3-a', file, stale);

    const refused = startIn('X3-a', dir('elsewhere'), entryOf(file, 'github').args);
    expectB1(refused, sentinel, 'cursor');
    // X3-f: the refusal does not say the stored binding is another entry's.
    expect(refused.stderr).not.toMatch(/another|different/);

    const output = await run('X3-a', () => runProtectMcp([]), dir('setup'));

    expect(output).toContain(`  cursor (${file})\n    ~ github: its binding was out of date; bound again\n`);
    expect(output.match(/^ {4}~ /gm)).toHaveLength(1);
    expect(idOf(entryOf(file, 'github').args)).toBe(id);
    expect(fs.readFileSync(file, 'utf-8')).toBe(bound);
    expect(await store().getBinding('cursor', 'github')).toEqual(record);
    expectStarted(startIn('X3-a', dir('elsewhere'), entryOf(file, 'github').args), sentinel);
  });

  it('X3-b: the same with a child argument changed: the binding takes the command first, then the entry its id, and it starts', async () => {
    const { file, sentinel, id } = await homeRecord('X3-b');
    const stale = newBindingId();
    setId(file, 'github', stale);
    plant('X3-b', file, stale);
    const config = JSON.parse(fs.readFileSync(file, 'utf-8'));
    config.mcpServers.github.args = [...config.mcpServers.github.args, 'extra'];
    write(file, config);

    const output = await run('X3-b', () => runProtectMcp([]), dir('setup'));

    expect(output).toContain(
      `  cursor (${file})\n    ~ github: its binding was out of date; bound again; its command or arguments changed since it was bound\n`,
    );
    expect(output.match(/^ {4}~ /gm)).toHaveLength(1);
    const entry = entryOf(file, 'github');
    expect(idOf(entry.args)).toBe(id);
    expect(await store().getBinding('cursor', 'github')).toMatchObject({ id, file, commandDigest: digestOf(entry.args) });
    expectStarted(startIn('X3-b', dir('elsewhere'), entry.args), sentinel);
  });

  it('X3-c: a .mcp.json entry whose id was replaced is left, its line gives the new-name remedy, and nothing is written', async () => {
    const { a, file } = await projectRecord('X3-c');
    const stale = newBindingId();
    setId(file, 'github', stale);
    plant('X3-c', file, stale);
    const before = fs.readFileSync(file, 'utf-8');
    const record = await store().getBinding('claude-code', 'github');

    const output = await run('X3-c', () => runProtectMcp([]), a);

    expect(output).toContain(`  claude-code (.mcp.json)\n    ? github: not bound: ${OTHER_ID_PROJECT}\n`);
    expect(output).not.toContain('mcp-forget');
    expect(fs.readFileSync(file, 'utf-8')).toBe(before);
    expect(await store().getBinding('claude-code', 'github')).toEqual(record);
  });

  it('X3-d: a home entry at its binding\'s place with no --binding is given its binding\'s id, and starts', async () => {
    const { file, sentinel, id } = await homeRecord('X3-d');
    const bound = fs.readFileSync(file, 'utf-8');
    setId(file, 'github', undefined);

    const output = await run('X3-d', () => runProtectMcp([]), dir('setup'));

    expect(output).toContain(`  cursor (${file})\n    ~ github: its binding was out of date; bound again\n`);
    expect(idOf(entryOf(file, 'github').args)).toBe(id);
    expect(fs.readFileSync(file, 'utf-8')).toBe(bound);
    expectStarted(startIn('X3-d', dir('elsewhere'), entryOf(file, 'github').args), sentinel);
  });

  it('X3-e: a stale home entry and a copy carrying its binding, seen in one run, converge: the entry carries the binding\'s id, the copy is refused, and a second run writes nothing', async () => {
    const { file, entry, sentinel, id } = await homeRecord('X3-e');
    const p = dir('p');
    const copy = write(path.join(p, '.mcp.json'), { mcpServers: { github: entry } });
    const stale = newBindingId();
    setId(file, 'github', stale);
    plant('X3-e', file, stale);

    await run('X3-e', () => runProtectMcp([]), p);

    const record = await store().getBinding('cursor', 'github');
    expect(idOf(entryOf(file, 'github').args)).toBe(record!.id);
    plant('X3-e', file, record!.id);
    expect(idOf(entryOf(copy, 'github').args)).toBe(id);
    expectB1(startIn('X3-e', p, entryOf(copy, 'github').args), sentinel, 'cursor');
    expectStarted(startIn('X3-e', dir('elsewhere'), entryOf(file, 'github').args), sentinel);

    const files = [fs.readFileSync(file, 'utf-8'), fs.readFileSync(copy, 'utf-8')];
    await run('X3-e', () => runProtectMcp([]), p);
    expect([fs.readFileSync(file, 'utf-8'), fs.readFileSync(copy, 'utf-8')]).toEqual(files);
    expect(await store().getBinding('cursor', 'github')).toEqual(record);
  });

  it('T9: after the binding\'s id is replaced in the store, protect-mcp writes it into the home entry; the entry starts, and one carrying the old id is refused', async () => {
    const { file, entry, sentinel, id } = await homeRecord('T9');
    const record = await store().getBinding('cursor', 'github');
    const replaced = newBindingId();
    await store().storeBinding('cursor', 'github', { ...record!, id: replaced });

    await run('T9', () => runProtectMcp([]), dir('setup'));

    expect(idOf(entryOf(file, 'github').args)).toBe(replaced);
    plant('T9', file, replaced);
    expect(idOf(entry.args)).toBe(id);
    expectStarted(startIn('T9', dir('elsewhere'), entryOf(file, 'github').args), sentinel);
    expectB1(startIn('T9', dir('elsewhere'), entry.args), sentinel, 'cursor');
  });

  it('st1: a .mcp.json entry carrying another id: after protect-mcp the file and the binding are byte-identical, and it is refused with B1 in its project', async () => {
    const { a, file, sentinel } = await projectRecord('st1');
    const stale = newBindingId();
    setId(file, 'github', stale);
    plant('st1', file, stale);
    const before = fs.readFileSync(file, 'utf-8');
    const record = await store().getBinding('claude-code', 'github');

    await run('st1', () => runProtectMcp([]), a);

    expect(fs.readFileSync(file, 'utf-8')).toBe(before);
    expect(await store().getBinding('claude-code', 'github')).toEqual(record);
    expectB1(startIn('st1', a, entryOf(file, 'github').args), sentinel, 'claude-code');
  });

  it('st2: following the printed remedy, the server added again under a new name with its values is bound and starts', async () => {
    const { a, file } = await projectRecord('st2');
    const stale = newBindingId();
    setId(file, 'github', stale);
    plant('st2', file, stale);
    const output = await run('st2', () => runProtectMcp([]), a);
    expect(output).toContain(OTHER_ID_PROJECT);

    // Add it again under a new name with its values, remove this entry, and run protect-mcp.
    const sentinel = path.join(scratch, 'renamed-started.json');
    const config = JSON.parse(fs.readFileSync(file, 'utf-8'));
    delete config.mcpServers.github;
    config.mcpServers['github-2'] = plain(sentinel);
    write(file, config);
    const again = await run('st2', () => runProtectMcp([]), a);

    expect(again).toContain('  + claude-code/github-2\n');
    const entry = entryOf(file, 'github-2');
    plant('st2', file, idOf(entry.args));
    expect(await store().getBinding('claude-code', 'github-2')).toMatchObject({ id: idOf(entry.args), scope: 'project' });
    expectStarted(startIn('st2', a, entry.args), sentinel);
  });
});

describe('the state of the file a binding names decides the line for an entry bound elsewhere', () => {
  const elsewhere = (file: string) =>
    `the secrets stored under claude-code/github are bound to server "github" in ${file}. `
    + `To run this server as well, add it again under a new name with its values and run \`npx secretless-ai protect-mcp\`.`;

  it('e1: a project binding whose .mcp.json was deleted, with no backup of it, leaves a reader in another .mcp.json with the missing-file clause, and no line names mcp-forget', async () => {
    const { file } = await projectRecord('e1');
    fs.rmSync(file);
    fs.rmSync(backupDir(), { recursive: true, force: true });
    const b = real(dir('b'));
    write(path.join(b, '.mcp.json'), { mcpServers: { github: wrappedUnbound('claude-code', 'github') } });

    const output = await run('e1', () => runProtectMcp([]), b);

    expect(output).toContain(`    ? github: not bound: ${elsewhere(file)} ${file} no longer exists.\n`);
    expect(output).not.toContain('mcp-forget');
  });

  it('e2: a binding whose file is in a directory this run cannot search reads unknown: the line names the code and no missing file, and nothing is written', async () => {
    const { a, file } = await projectRecord('e2');
    const b = real(dir('b'));
    const reader = write(path.join(b, '.mcp.json'), { mcpServers: { github: wrappedUnbound('claude-code', 'github') } });
    const before = fs.readFileSync(reader, 'utf-8');
    const record = await store().getBinding('claude-code', 'github');
    fs.chmodSync(a, 0o600);
    let output: string;
    try {
      output = await run('e2', () => runProtectMcp([]), b);
    } finally {
      fs.chmodSync(a, 0o700);
    }

    expect(output).toContain(`    ? github: not bound: ${elsewhere(file)} ${file} could not be checked (EACCES).\n`);
    expect(output).not.toContain('no longer exists');
    expect(fs.readFileSync(reader, 'utf-8')).toBe(before);
    expect(await store().getBinding('claude-code', 'github')).toEqual(record);
  });

  it('e4: where this machine\'s backup of the old file holds the stored values, the moved entry is bound again with no missing-file clause', async () => {
    const { a, a2, moved } = await movedProject('e4');

    const output = await run('e4', () => runProtectMcp([]), a2);

    expect(output).toContain(`    + github: bound again; its project directory moved from ${a}\n`);
    expect(output).not.toMatch(/no longer exists|not found on this machine|could not be checked/);
    plant('e4', moved, idOf(entryOf(moved, 'github').args));
  });

  it('e5: a home binding whose config file was deleted is taken over by the one home entry that reads its pair', async () => {
    const { file } = await homeRecord('e5');
    fs.rmSync(file);
    const settings = write(path.join(home, '.claude', 'settings.json'), { mcpServers: { github: wrappedUnbound('cursor', 'github') } });

    const output = await run('e5', () => runProtectMcp([]), dir('setup'));

    expect(output).toContain(`    + github: bound (took over the binding of server "github", no longer in ${file})\n`);
    const record = await store().getBinding('cursor', 'github');
    expect(record).toMatchObject({ scope: 'home', file: settings, server: 'github' });
    expect(idOf(entryOf(settings, 'github').args)).toBe(record!.id);
    plant('e5', settings, record!.id);
  });

  it('e5: with two home entries reading its pair, each is left with the others reason, and nothing is written', async () => {
    const { file } = await homeRecord('e5');
    fs.rmSync(file);
    const settings = write(path.join(home, '.claude', 'settings.json'), { mcpServers: { github: wrappedUnbound('cursor', 'github') } });
    const claudeJson = write(path.join(home, '.claude.json'), { mcpServers: { github: wrappedUnbound('cursor', 'github') } });
    const record = await store().getBinding('cursor', 'github');
    const before = [fs.readFileSync(settings, 'utf-8'), fs.readFileSync(claudeJson, 'utf-8')];

    const output = await run('e5', () => runProtectMcp([]), dir('setup'));

    const others = (other: string) =>
      `    ? github: not bound: cursor/github is also read by server "github" in ${other}, and the secrets stored under a name are bound to one entry only.`;
    expect(output).toContain(others(claudeJson));
    expect(output).toContain(others(settings));
    expect(output).not.toContain('took over');
    expect(await store().getBinding('cursor', 'github')).toEqual(record);
    expect([fs.readFileSync(settings, 'utf-8'), fs.readFileSync(claudeJson, 'utf-8')]).toEqual(before);
  });

  it('e6: a dangling symlink at a binding\'s file reads absent, and a file there reads present', () => {
    const link = path.join(scratch, 'link.json');
    fs.symlinkSync(path.join(scratch, 'nowhere.json'), link);
    const there = write(path.join(scratch, 'there.json'), {});

    expect(protectModule.recordFileState({ file: link })).toEqual({ state: 'absent' });
    expect(protectModule.recordFileState({ file: there })).toEqual({ state: 'present' });
  });
});

describe('no output carries a binding id', () => {
  it('the stdout and stderr every cell above captured hold none of the ids planted, and each planted config holds its id', () => {
    expect(planted.length).toBeGreaterThan(0);
    expect(captured.length).toBeGreaterThan(0);
    let hits = 0;
    for (const { cell, id, config } of planted) {
      expect(config.includes(id), `${cell}: the scratch config holds the id it planted`).toBe(true);
      hits += captured.filter((c) => c.text.includes(id)).length;
    }
    expect(hits).toBe(0);
  });
});
