import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { protectMcp } from './protect';
import { McpVault } from './vault';
import { rewriteConfig } from './rewrite';

/**
 * A binding after its entry, its file or its store changed outside
 * protect-mcp. mcp-unprotect deletes a pair only where its binding names a
 * file it restored. No output carries a binding id.
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

/** The run started the server: exit 0 and the sentinel written. */
function expectStarted(res: ReturnType<typeof startIn>, sentinel: string) {
  expect(res.status, res.stderr).toBe(0);
  expect(fs.existsSync(sentinel)).toBe(true);
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
