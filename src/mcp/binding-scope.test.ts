import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { protectMcp } from './protect';
import { McpVault } from './vault';
import { BINDING_COPY_READ_LIMIT } from './discover';

/**
 * Where a bound entry starts. A project-level binding is honoured only in its
 * project's directory or below it, a binding found in another project-level
 * config visible from the start directory is refused, and protect-mcp
 * replaces a home binding it finds outside its own entry. No output carries a
 * binding id.
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
const FIX =
  "secretless-mcp: Run 'npx secretless-ai mcp-status' to see which config entries are bound, then 'npx secretless-ai protect-mcp' to bind the entries it protected.";
const NOT_STARTED = 'so no secret was read. The server was not started.';
const ID = /^[0-9a-f]{32}$/;

/** Every output a cell captured, and every id a cell planted with the config text that holds it (T5). */
const captured: Array<{ cell: string; text: string }> = [];
const planted: Array<{ cell: string; id: string; config: string }> = [];

let home: string;
let scratch: string;
let bin: string;
let saved: Record<'HOME' | 'USER' | 'PATH', string | undefined>;

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-scope-home-'));
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-scope-dirs-'));
  bin = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-scope-bin-'));
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
  for (const dir of [home, scratch, bin]) fs.rmSync(dir, { recursive: true, force: true });
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

function childEnv(): NodeJS.ProcessEnv {
  return { PATH: process.env.PATH, HOME: home, SECRETLESS_OS_KEYCHAIN: 'off', OPENA2A_TELEMETRY: 'off' };
}

/** A stub server: writes its env to `sentinel`, so a test sees it started. */
function stubArgs(sentinel: string): string[] {
  return ['-e', `require('fs').writeFileSync(${JSON.stringify(sentinel)}, JSON.stringify(process.env))`];
}

/** The built wrapper started in `cwd` with an entry's args, as a client starts it; its output is kept for T5. */
function startIn(cell: string, cwd: string, args: string[]) {
  const res = spawnSync(process.execPath, [WRAPPER_JS, ...args], { cwd, encoding: 'utf-8', env: childEnv() });
  captured.push({ cell, text: `${res.stdout}${res.stderr}` });
  return res;
}

/** A command of the built CLI run in `cwd`; its output is kept for T5. */
function runCliIn(cell: string, cwd: string, args: string[]): string {
  const res = spawnSync(process.execPath, [CLI_PATH, ...args], { cwd, encoding: 'utf-8', env: childEnv() });
  captured.push({ cell, text: `${res.stdout}${res.stderr}` });
  expect(res.status, `${args.join(' ')}: ${res.stderr}`).toBe(0);
  return res.stdout;
}

function entryOf(file: string, name: string): { command: string; args: string[] } {
  return JSON.parse(fs.readFileSync(file, 'utf-8')).mcpServers[name];
}

/** The value of the --binding before an entry's `--`. */
function idOf(args: string[]): string | undefined {
  const own = args.slice(0, args.indexOf('--'));
  const at = own.indexOf('--binding');
  return at === -1 ? undefined : own[at + 1];
}

/** `github` in the project's .mcp.json, protected by protect-mcp: a project-level binding. */
async function projectRecord(cell: string) {
  const a = dir('a');
  const sentinel = path.join(scratch, 'started.json');
  const file = write(path.join(a, '.mcp.json'), {
    mcpServers: { github: { command: process.execPath, args: stubArgs(sentinel), env: { [NAME]: VALUE } } },
  });
  await protectMcp({ projectDir: a, wrapperPath: WRAPPER_PATH });
  const entry = entryOf(file, 'github');
  const id = idOf(entry.args);
  expect(ID.test(id ?? ''), 'the entry carries a binding id').toBe(true);
  planted.push({ cell, id: id!, config: fs.readFileSync(file, 'utf-8') });
  return { a, file, entry, sentinel, id: id! };
}

/** `github` in the home cursor config, protected by protect-mcp: a home binding. */
async function homeRecord(cell: string) {
  const sentinel = path.join(scratch, 'started.json');
  const file = write(path.join(home, '.cursor', 'mcp.json'), {
    mcpServers: { github: { command: process.execPath, args: stubArgs(sentinel), env: { [NAME]: VALUE } } },
  });
  await protectMcp({ projectDir: dir('setup'), wrapperPath: WRAPPER_PATH });
  const entry = entryOf(file, 'github');
  const id = idOf(entry.args);
  expect(ID.test(id ?? ''), 'the entry carries a binding id').toBe(true);
  planted.push({ cell, id: id!, config: fs.readFileSync(file, 'utf-8') });
  return { file, entry, sentinel, id: id! };
}

const PROJECT_ENTRY = 'client "claude-code", server "github"';
const HOME_ENTRY = 'client "cursor", server "github"';
const b3 = (entry: string, project: string, started: string) =>
  `secretless-mcp: The secrets stored for ${entry} are bound to the project in ${project}, and this entry was started in ${started}, ${NOT_STARTED}`;
const b4 = (entry: string, file: string) =>
  `secretless-mcp: The binding of the secrets stored for ${entry} also appears in ${file}, and a bound entry starts only from the config protect-mcp bound it in, ${NOT_STARTED} Remove that copy.`;

/** The run started the server: exit 0 and the sentinel written. */
function expectStarted(res: ReturnType<typeof startIn>, sentinel: string) {
  expect(res.status, res.stderr).toBe(0);
  expect(fs.existsSync(sentinel)).toBe(true);
  fs.rmSync(sentinel, { force: true });
}

/** The run started nothing: exit 1, the refusal on stderr, the fix line last, and no sentinel. */
function expectRefused(res: ReturnType<typeof startIn>, sentinel: string, line: string) {
  expect(res.status).toBe(1);
  expect(res.stderr).toBe(`${line}\n${FIX}\n`);
  expect(fs.existsSync(sentinel)).toBe(false);
}

describe('T1: a project-level binding is honoured only in its project directory or below it', () => {
  it('T1a: started in the project directory, the server starts', async () => {
    const { a, entry, sentinel } = await projectRecord('T1a');
    expectStarted(startIn('T1a', a, entry.args), sentinel);
  });

  it('T1b: started in a subdirectory of the project, the server starts', async () => {
    const { a, entry, sentinel } = await projectRecord('T1b');
    const sub = path.join(a, 'sub');
    fs.mkdirSync(sub);
    expectStarted(startIn('T1b', sub, entry.args), sentinel);
  });

  it('T1c: started in another directory holding a byte copy of the .mcp.json, it exits 1 naming the project', async () => {
    const { a, file, entry, sentinel } = await projectRecord('T1c');
    const b = dir('b');
    fs.copyFileSync(file, path.join(b, '.mcp.json'));
    expectRefused(startIn('T1c', b, entry.args), sentinel, b3(PROJECT_ENTRY, real(a), real(b)));
  });

  it('T1d: started through a symlink to the project directory, the server starts', async () => {
    const { a, entry, sentinel } = await projectRecord('T1d');
    const link = path.join(scratch, 'link');
    fs.symlinkSync(a, link);
    expectStarted(startIn('T1d', link, entry.args), sentinel);
  });

  it('T1e: once the bound .mcp.json is deleted, it exits 1 with the project line', async () => {
    const { a, file, entry, sentinel } = await projectRecord('T1e');
    fs.rmSync(file);
    const res = startIn('T1e', a, entry.args);
    expectRefused(
      res,
      sentinel,
      `secretless-mcp: The secrets stored for ${PROJECT_ENTRY} are bound to the project in ${real(a)}, and ${path.join(real(a), '.mcp.json')} could not be resolved (ENOENT), ${NOT_STARTED}`,
    );
  });
});

describe('T2: a home binding found in a project-level config visible from the start directory is refused', () => {
  it('T2a: a copy in the project .mcp.json exits 1 naming that file; mcp-status says the entry does not start and names protect-mcp', async () => {
    const { entry, sentinel } = await homeRecord('T2a');
    const p = dir('p');
    write(path.join(p, '.mcp.json'), { mcpServers: { github: entry } });
    const copy = path.join(real(p), '.mcp.json');
    expectRefused(startIn('T2a', p, entry.args), sentinel, b4(HOME_ENTRY, copy));
    const status = runCliIn('T2a', p, ['mcp-status']);
    expect(status).toContain(`    ? github: protected and bound, but its binding also appears in ${copy}, so the wrapper does not start it\n`);
    expect(status).toContain(
      '  Run `npx secretless-ai protect-mcp` to replace each home binding found outside its own entry; a copy of it then no longer starts.\n',
    );
  });

  it('T2b: a copy in the project .cursor/mcp.json exits 1', async () => {
    const { entry, sentinel } = await homeRecord('T2b');
    const p = dir('p');
    write(path.join(p, '.cursor', 'mcp.json'), { mcpServers: { github: entry } });
    expectRefused(startIn('T2b', p, entry.args), sentinel, b4(HOME_ENTRY, path.join(real(p), '.cursor', 'mcp.json')));
  });

  it('T2c: started two directories below a project whose .mcp.json holds the copy, it exits 1', async () => {
    const { entry, sentinel } = await homeRecord('T2c');
    const p = dir('p');
    write(path.join(p, '.mcp.json'), { mcpServers: { github: entry } });
    expectRefused(startIn('T2c', dir('p', 'x', 'y'), entry.args), sentinel, b4(HOME_ENTRY, path.join(real(p), '.mcp.json')));
  });

  it('T2d: the id written with JSON escapes inside a string is found', async () => {
    const { entry, sentinel, id } = await homeRecord('T2d');
    const p = dir('p');
    const escaped = [...id].map((c) => `\\u00${c.charCodeAt(0).toString(16)}`).join('');
    const text = `{"mcpServers": {"github": {"command": "x", "args": ["--binding", "${escaped}"]}}}`;
    write(path.join(p, '.mcp.json'), text);
    expect(text.includes(id)).toBe(false);
    expectRefused(startIn('T2d', p, entry.args), sentinel, b4(HOME_ENTRY, path.join(real(p), '.mcp.json')));
  });

  it('T2e: a .vscode/mcp.json that is not valid JSON and holds the id exits 1', async () => {
    const { entry, sentinel, id } = await homeRecord('T2e');
    const p = dir('p');
    write(path.join(p, '.vscode', 'mcp.json'), `{ "servers": { "github": { "args": ["--binding", "${id}" `);
    expectRefused(startIn('T2e', p, entry.args), sentinel, b4(HOME_ENTRY, path.join(real(p), '.vscode', 'mcp.json')));
  });

  it('T2f: the same file without the id: the server starts', async () => {
    const { entry, sentinel } = await homeRecord('T2f');
    const p = dir('p');
    write(path.join(p, '.vscode', 'mcp.json'), '{ "servers": { "github": { "args": ["--binding", "not-the-id" ');
    expectStarted(startIn('T2f', p, entry.args), sentinel);
  });

  it('T2g: a .mcp.json that is a directory is skipped: the server starts', async () => {
    const { entry, sentinel } = await homeRecord('T2g');
    const p = dir('p');
    fs.mkdirSync(path.join(p, '.mcp.json'));
    expectStarted(startIn('T2g', p, entry.args), sentinel);
  });

  it('T2h: a project-level config over the read bound exits 1; one at the bound is read', async () => {
    const { entry, sentinel } = await homeRecord('T2h');
    expect(BINDING_COPY_READ_LIMIT).toBe(1024 * 1024);
    const p = dir('p');
    const file = path.join(p, '.mcp.json');
    // `{"pad": "` and `"}` are 11 bytes.
    const padded = (size: number) => `{"pad": "${'x'.repeat(size - 11)}"}`;
    write(file, padded(BINDING_COPY_READ_LIMIT));
    expect(fs.statSync(file).size).toBe(BINDING_COPY_READ_LIMIT);
    expectStarted(startIn('T2h', p, entry.args), sentinel);
    write(file, padded(BINDING_COPY_READ_LIMIT + 1));
    expect(fs.statSync(file).size).toBe(BINDING_COPY_READ_LIMIT + 1);
    expectRefused(
      startIn('T2h', p, entry.args),
      sentinel,
      `secretless-mcp: ${path.join(real(p), '.mcp.json')} could not be checked for a copy of the binding of the secrets stored for ${HOME_ENTRY} (it is larger than ${BINDING_COPY_READ_LIMIT} bytes), ${NOT_STARTED}`,
    );
  });

  it('T2i: no copy anywhere: the server starts', async () => {
    const { entry, sentinel } = await homeRecord('T2i');
    expectStarted(startIn('T2i', dir('p'), entry.args), sentinel);
  });
});

describe('T3: a project binding found in a nested project-level config is refused', () => {
  it('T3: a .mcp.json in a subdirectory holding the project id exits 1 started there; mcp-status names removing the copy', async () => {
    const { a, entry, sentinel } = await projectRecord('T3');
    const x = path.join(a, 'x');
    write(path.join(x, '.mcp.json'), { mcpServers: { github: entry } });
    const nested = path.join(real(a), 'x', '.mcp.json');
    expectRefused(startIn('T3', x, entry.args), sentinel, b4(PROJECT_ENTRY, nested));
    expectStarted(startIn('T3', a, entry.args), sentinel);
    const status = runCliIn('T3', a, ['mcp-status']);
    expect(status).toContain('    + github: protected and bound\n');
    const inX = runCliIn('T3', x, ['mcp-status']);
    expect(inX).toContain(`    ? github: carries the binding of the entry for server "github" in ${path.join(a, '.mcp.json')}, but its binding also appears in ${nested}, so the wrapper does not start it\n`);
    expect(inX).toContain('  Remove each copy of a project binding named above; protect-mcp does not replace a project binding.\n');
  });
});

describe('T4: protect-mcp replaces a home binding it finds in a project .mcp.json', () => {
  it('T4: the home entry and the binding take a new id, the copy is not written and no longer starts, and the home entry starts', async () => {
    const { file, entry, sentinel, id } = await homeRecord('T4');
    const p = dir('p');
    const copy = write(path.join(p, '.mcp.json'), { mcpServers: { github: entry } });
    const copy0 = fs.readFileSync(copy);
    const before = await store().getBinding('cursor', 'github');

    const out = runCliIn('T4', p, ['protect-mcp']);

    const own = entryOf(file, 'github');
    const next = idOf(own.args);
    expect(ID.test(next ?? '') && next !== id, 'the entry carries a new binding id').toBe(true);
    planted.push({ cell: 'T4', id: next!, config: fs.readFileSync(file, 'utf-8') });
    const after = await store().getBinding('cursor', 'github');
    expect(after?.id === next, 'the stored binding holds the new id').toBe(true);
    expect({ ...after, id: '', boundAt: '', boundBy: '' }).toEqual({ ...before, id: '', boundAt: '', boundBy: '' });
    expect(JSON.stringify(own.args.map((arg) => (arg === next ? id : arg))) === JSON.stringify(entry.args), 'the home entry changed only in its id').toBe(true);
    expect(fs.readFileSync(copy).equals(copy0)).toBe(true);
    expect(out).toContain(
      `    ? github: a copy of a bound entry: it carried the binding of server "github" in ${file}; the binding was replaced, and this entry no longer starts. `,
    );

    const q = dir('q');
    expectRefused(
      startIn('T4', q, entry.args),
      sentinel,
      `secretless-mcp: The binding in the config entry for ${HOME_ENTRY} does not match the one stored for its secrets, which belongs to server "github" in ${file}, ${NOT_STARTED}`,
    );
    expectStarted(startIn('T4', q, own.args), sentinel);
  });
});

describe('T6: a copy within ~/.claude.json under another project key', () => {
  it('T6: it starts (a home config is not searched for copies) until protect-mcp replaces the binding, then exits 1 with the binding line', async () => {
    const sentinel = path.join(scratch, 'started.json');
    const file = write(path.join(home, '.claude.json'), {
      mcpServers: { github: { command: process.execPath, args: stubArgs(sentinel), env: { [NAME]: VALUE } } },
    });
    const q = dir('q');
    await protectMcp({ projectDir: q, wrapperPath: WRAPPER_PATH });
    const config = JSON.parse(fs.readFileSync(file, 'utf-8'));
    const entry = config.mcpServers.github;
    const id = idOf(entry.args);
    expect(ID.test(id ?? ''), 'the entry carries a binding id').toBe(true);
    const elsewhere = dir('elsewhere');
    config.projects = { [elsewhere]: { mcpServers: { github: entry } } };
    write(file, config);
    planted.push({ cell: 'T6', id: id!, config: fs.readFileSync(file, 'utf-8') });

    expectStarted(startIn('T6', q, entry.args), sentinel);

    runCliIn('T6', q, ['protect-mcp']);
    const now = JSON.parse(fs.readFileSync(file, 'utf-8'));
    const next = idOf(now.mcpServers.github.args);
    expect(ID.test(next ?? '') && next !== id, 'the entry carries a new binding id').toBe(true);
    planted.push({ cell: 'T6', id: next!, config: fs.readFileSync(file, 'utf-8') });
    const copied = now.projects[elsewhere].mcpServers.github;
    expect(idOf(copied.args) === id, 'the copy keeps the old id').toBe(true);

    expectRefused(
      startIn('T6', q, copied.args),
      sentinel,
      `secretless-mcp: The binding in the config entry for client "claude-code", server "github" does not match the one stored for its secrets, which belongs to server "github" in ${file}, ${NOT_STARTED}`,
    );
    expectStarted(startIn('T6', q, now.mcpServers.github.args), sentinel);
  });
});

describe('T5: no output carries a binding id', () => {
  it('the stdout and stderr every cell above captured hold none of the ids planted, and each planted config holds its id', () => {
    expect(planted.length).toBeGreaterThan(0);
    expect(captured.length).toBeGreaterThan(0);
    let hits = 0;
    for (const { cell, id, config } of planted) {
      expect(config.includes(id), `${cell}: the scratch config holds the id it planted`).toBe(true);
      hits += captured.filter((c) => c.text.includes(id)).length;
    }
    console.log(`T5: ${planted.length} planted id(s), ${captured.length} captured output(s), ${hits} holding a planted id`);
    expect(hits).toBe(0);
  });
});
