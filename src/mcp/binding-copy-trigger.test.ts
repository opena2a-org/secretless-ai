import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { protectMcp } from './protect';
import { McpVault } from './vault';
import { BINDING_COPY_READ_LIMIT } from './discover';
import { checkStart } from './start-check';
import { createBackend } from '../backends/factory';
import { runProtectMcp } from '../commands/mcp';
import { MemoryStore } from './binding-store-double.test-support';

/**
 * protect-mcp run in a directory replaces a home binding that the wrapper's
 * own check (checkLaunchPlace) finds in a copy from that directory, in a
 * project-level config it does not rewrite or in one above it: once per pair
 * in a run, reading those files for the id only and writing nothing into
 * them. A file the check could not read for the id replaces nothing and is
 * named, and a project binding is never replaced. Then the order of the two
 * steps of the wrapper's fix: protect-mcp first replaces the binding, and
 * removing the copy first leaves it as it was.
 *
 * Every store is an in-memory double: no keychain, no network. Values are
 * assembled at run time and are not credentials.
 */

vi.mock('../backends/factory', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../backends/factory')>();
  return { ...actual, createBackend: vi.fn(actual.createBackend) };
});

// The wrapper protect-mcp writes into a config: this build's, as the built
// CLI writes it, so its runs read these entries as on its own wrapper.
const WRAPPER_PATH = path.resolve(__dirname, '..', '..', 'dist', 'mcp-wrapper.js');
const NAME = ['MY', 'SERVICE', 'API', 'KEY'].join('_');
const VALUE = ['stand', 'in', 'value', String(process.pid)].join('-');
const ID = /^[0-9a-f]{32}$/;
const HEX_RUN = /[0-9a-f]{32}/i;

let home: string;
let scratch: string;
let memory: MemoryStore;
let saved: Record<'HOME' | 'USER', string | undefined>;

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-trigger-home-'));
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-trigger-dirs-'));
  saved = { HOME: process.env.HOME, USER: process.env.USER };
  process.env.HOME = home;
  delete process.env.USER;
  write(path.join(home, '.secretless-ai', 'config.json'), { backend: 'local' });
  // mcp-status builds protect-mcp's store for its plan only where its directory exists.
  fs.mkdirSync(path.join(home, '.secretless-ai', 'mcp-vault'), { recursive: true });
  memory = new MemoryStore();
  vi.mocked(createBackend).mockImplementation(() => memory);
});

afterEach(() => {
  vi.mocked(createBackend).mockReset();
  for (const [name, value] of Object.entries(saved)) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
  for (const d of [home, scratch]) fs.rmSync(d, { recursive: true, force: true });
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
const vault = () => new McpVault({ backend: memory });
const plain = () => ({ command: process.execPath, args: ['-e', 'x'], env: { [NAME]: VALUE } });

function entryOf(file: string, server = 'github'): { command: string; args: string[] } {
  return JSON.parse(fs.readFileSync(file, 'utf-8')).mcpServers[server];
}

/** The id an entry's args carry before the wrapper's `--`, and the command after it. */
function split(args: string[]): { id: string | undefined; child: string[] } {
  const at = args.indexOf('--');
  const own = args.slice(0, at);
  const b = own.indexOf('--binding');
  return { id: b === -1 ? undefined : own[b + 1], child: args.slice(at + 1) };
}

/** A server in a home config, protected by protect-mcp run in an empty directory: a home binding. */
async function homeBinding(client = 'cursor', relativePath = path.join('.cursor', 'mcp.json'), server = 'github') {
  const file = write(path.join(home, relativePath), { mcpServers: { [server]: plain() } });
  await protectMcp({ projectDir: dir('setup'), wrapperPath: WRAPPER_PATH });
  const entry = entryOf(file, server);
  const id = split(entry.args).id;
  expect(ID.test(id ?? ''), 'the entry carries a binding id').toBe(true);
  expect((await vault().getBinding(client, server))?.scope).toBe('home');
  return { file, entry, id: id! };
}

/** The wrapper's checks for an entry's args, started in `startDir`, as the wrapper and mcp-status run them. */
function startFrom(startDir: string, args: string[], client = 'cursor', server = 'github') {
  const { id, child } = split(args);
  return checkStart(vault(), { client, server, binding: id, command: child[0], args: child.slice(1) }, { startDir, home });
}

/** A command of the CLI in this process, from `cwd`, with what it prints. */
async function run(command: () => Promise<number>, cwd: string): Promise<{ code: number; output: string }> {
  const lines: string[] = [];
  const capture = (...parts: unknown[]) => { lines.push(parts.map(String).join(' ')); };
  const log = vi.spyOn(console, 'log').mockImplementation(capture);
  const error = vi.spyOn(console, 'error').mockImplementation(capture);
  const at = vi.spyOn(process, 'cwd').mockReturnValue(cwd);
  try {
    const code = await command();
    return { code, output: lines.join('\n') };
  } finally {
    log.mockRestore();
    error.mockRestore();
    at.mockRestore();
  }
}

/** The five places a copy is found from W that protect-mcp does not rewrite: four in W, and the .mcp.json above it. */
const PLACES: Array<[string, 'w' | 'parent', string]> = [
  ['<W>/.cursor/mcp.json', 'w', path.join('.cursor', 'mcp.json')],
  ['<W>/.vscode/mcp.json', 'w', path.join('.vscode', 'mcp.json')],
  ['<W>/.windsurf/mcp.json', 'w', path.join('.windsurf', 'mcp.json')],
  ['<W>/mcp.json', 'w', 'mcp.json'],
  ['<parent of W>/.mcp.json', 'parent', '.mcp.json'],
];

describe('X2-b: protect-mcp replaces a home binding the wrapper\'s check finds in a copy from where it runs', () => {
  it.each(PLACES)(
    'a copy in %s: one new id, the bound entry carries it, the copy is byte-identical; from W the bound entry starts and the copy is refused by checkLaunch',
    async (_label, base, relativePath) => {
      const { file, entry, id } = await homeBinding();
      const parent = dir('parent');
      const w = dir('parent', 'w');
      const root = base === 'w' ? w : parent;
      const copy = write(path.join(root, relativePath), { mcpServers: { github: entry } });
      const before = fs.readFileSync(copy);
      // The wrapper refuses the bound entry from W: the copy is found there.
      expect(await startFrom(w, entry.args)).toMatchObject({
        starts: false,
        place: { refused: 'copy-found', file: path.join(real(root), relativePath) },
      });
      const writes = memory.bindingWrites.length;

      await protectMcp({ projectDir: w, wrapperPath: WRAPPER_PATH });

      const record = await vault().getBinding('cursor', 'github');
      expect(ID.test(record?.id ?? '') && record?.id !== id, 'the record holds a new id').toBe(true);
      expect(memory.bindingWrites.length - writes, 'one binding written').toBe(1);
      expect(split(entryOf(file).args).id).toBe(record!.id);
      expect(fs.readFileSync(copy).equals(before), 'the copy is byte-identical').toBe(true);
      expect((await startFrom(w, entryOf(file).args)).starts).toBe(true);
      const copied = await startFrom(w, entry.args);
      expect(copied).toMatchObject({ starts: false, launch: { refused: 'other-binding' } });
      expect('place' in copied).toBe(false);
    },
  );

  it('copies in all five places at once: the id changes once, the five files are byte-identical, the bound entry starts and each copy is refused by checkLaunch', async () => {
    const { file, entry, id } = await homeBinding();
    const parent = dir('parent');
    const w = dir('parent', 'w');
    const copies = PLACES.map(([, base, relativePath]) =>
      write(path.join(base === 'w' ? w : parent, relativePath), { mcpServers: { github: entry } }));
    const before = copies.map((copy) => fs.readFileSync(copy));
    const writes = memory.bindingWrites.length;

    await protectMcp({ projectDir: w, wrapperPath: WRAPPER_PATH });

    const record = await vault().getBinding('cursor', 'github');
    expect(ID.test(record?.id ?? '') && record?.id !== id, 'the record holds a new id').toBe(true);
    const written = memory.bindingWrites.slice(writes).map((text) => JSON.parse(text).id);
    expect(written, 'one new id, written once').toEqual([record!.id]);
    expect(split(entryOf(file).args).id).toBe(record!.id);
    copies.forEach((copy, i) => expect(fs.readFileSync(copy).equals(before[i]), `${copy} is byte-identical`).toBe(true));
    expect((await startFrom(w, entryOf(file).args)).starts).toBe(true);
    for (const copy of copies) {
      const copied = await startFrom(w, entryOf(copy).args);
      expect(copied, copy).toMatchObject({ starts: false, launch: { refused: 'other-binding' } });
    }
  });

  it('a copy over the read bound replaces nothing, and protect-mcp names the file as the wrapper\'s check does', async () => {
    const { file, entry, id } = await homeBinding();
    const w = dir('parent', 'w');
    const copy = path.join(w, '.cursor', 'mcp.json');
    write(copy, JSON.stringify({ mcpServers: { github: entry }, pad: 'x'.repeat(BINDING_COPY_READ_LIMIT) }));
    expect(fs.statSync(copy).size).toBeGreaterThan(BINDING_COPY_READ_LIMIT);
    const writes = memory.bindingWrites.length;

    const { code, output } = await run(() => runProtectMcp([]), w);

    expect(code).toBe(0);
    expect((await vault().getBinding('cursor', 'github'))?.id).toBe(id);
    expect(memory.bindingWrites.length).toBe(writes);
    expect(split(entryOf(file).args).id).toBe(id);
    expect(output).toContain(
      `  ${path.join(real(w), '.cursor', 'mcp.json')}\n    ? could not be checked for a copy of the binding of server "github" in ${file} `
        + `(it is larger than ${BINDING_COPY_READ_LIMIT} bytes), so the binding was not replaced.\n`,
    );
    expect(HEX_RUN.test(output), 'an id is printed').toBe(false);
  });

  it('a copy that cannot be read replaces nothing, and protect-mcp names the file and the error code', async () => {
    const { file, entry, id } = await homeBinding();
    const w = dir('parent', 'w');
    const copy = write(path.join(w, '.cursor', 'mcp.json'), { mcpServers: { github: entry } });
    fs.chmodSync(copy, 0o000);
    const writes = memory.bindingWrites.length;

    const { code, output } = await run(() => runProtectMcp([]), w);

    expect(code).toBe(0);
    expect((await vault().getBinding('cursor', 'github'))?.id).toBe(id);
    expect(memory.bindingWrites.length).toBe(writes);
    expect(output).toContain(
      `  ${path.join(real(w), '.cursor', 'mcp.json')}\n    ? could not be checked for a copy of the binding of server "github" in ${file} `
        + '(it could not be read (EACCES)), so the binding was not replaced.\n',
    );
    expect(HEX_RUN.test(output), 'an id is printed').toBe(false);
  });

  it('a copy of a project binding\'s entry leaves the id as it is: protect-mcp never replaces a project binding', async () => {
    const a = dir('a');
    const file = write(path.join(a, '.mcp.json'), { mcpServers: { github: plain() } });
    await protectMcp({ projectDir: a, wrapperPath: WRAPPER_PATH });
    const entry = entryOf(file);
    const id = split(entry.args).id;
    expect((await vault().getBinding('claude-code', 'github'))).toMatchObject({ id, scope: 'project' });
    const copy = write(path.join(a, '.cursor', 'mcp.json'), { mcpServers: { github: entry } });
    const before = fs.readFileSync(copy);
    expect(await startFrom(a, entry.args, 'claude-code')).toMatchObject({ starts: false, place: { refused: 'copy-found' } });
    const writes = memory.bindingWrites.length;

    await protectMcp({ projectDir: a, wrapperPath: WRAPPER_PATH });

    expect((await vault().getBinding('claude-code', 'github'))?.id).toBe(id);
    expect(memory.bindingWrites.length).toBe(writes);
    expect(split(entryOf(file).args).id).toBe(id);
    expect(fs.readFileSync(copy).equals(before)).toBe(true);
  });

  it('protect-mcp names the file it found the copy in, says the binding was replaced, and says the project-level config was checked for a copy', async () => {
    const { file, entry } = await homeBinding();
    const w = dir('parent', 'w');
    write(path.join(w, '.cursor', 'mcp.json'), { mcpServers: { github: entry } });

    const { code, output } = await run(() => runProtectMcp([]), w);

    expect(code).toBe(0);
    expect(output).toContain(
      `  ${path.join(real(w), '.cursor', 'mcp.json')}\n    ? holds a copy of the binding of server "github" in ${file}; `
        + 'the binding was replaced, so the copy no longer starts. Remove the copy from this file.\n'
        + '  1 copied binding(s) replaced; those copies no longer start.\n',
    );
    expect(output).toContain('  cursor (.cursor/mcp.json)\n    ? not rewritten; checked for a copy of a binding: see mcp-status\n');
    expect(output).not.toContain('Protected servers start as before.');
    expect(HEX_RUN.test(output), 'an id is printed').toBe(false);
  });

  it('a project-level config no check read is still named as not checked', async () => {
    const w = dir('parent', 'w');
    write(path.join(w, '.cursor', 'mcp.json'), { mcpServers: { other: { command: process.execPath, args: ['-e', 'x'], env: {} } } });

    const { output } = await run(() => runProtectMcp([]), w);

    expect(output).toContain('  cursor (.cursor/mcp.json)\n    ? not checked: project-level config: see mcp-status\n');
    expect(output).not.toContain('checked for a copy of a binding');
  });
});

describe('X2-a: the order of the two steps of the wrapper\'s fix for a home binding found in a copy', () => {
  it('protect-mcp first: the id changes, the bound entry starts and the copy is refused by checkLaunch; the copy removed first: the id stays', async () => {
    const { file, entry, id } = await homeBinding();
    const w = dir('w');
    const copy = write(path.join(w, '.mcp.json'), { mcpServers: { github: entry } });
    const copyBytes = fs.readFileSync(copy);
    const found = { starts: false, place: { refused: 'copy-found', file: path.join(real(w), '.mcp.json') } };

    // (1) From W, the wrapper's checks refuse both entries: each finds the copy.
    expect(await startFrom(w, entryOf(file).args)).toMatchObject(found);
    expect(await startFrom(w, entryOf(copy).args)).toMatchObject(found);

    // (2) protect-mcp run in W: the record takes a new id, the bound entry carries it, and the copy is not written.
    await protectMcp({ projectDir: w, wrapperPath: WRAPPER_PATH });
    const record = await vault().getBinding('cursor', 'github');
    expect(ID.test(record?.id ?? '') && record?.id !== id, 'the record holds a new id').toBe(true);
    expect(split(entryOf(file).args).id).toBe(record!.id);
    expect(entryOf(copy).args).toEqual(entry.args);
    expect(fs.readFileSync(copy).equals(copyBytes), 'the copy is byte-identical').toBe(true);

    // (3) From W, the bound entry starts, and the copy is refused by checkLaunch, not by its place.
    expect((await startFrom(w, entryOf(file).args)).starts).toBe(true);
    const copied = await startFrom(w, entryOf(copy).args);
    expect(copied).toMatchObject({ starts: false, launch: { refused: 'other-binding' } });
    expect('place' in copied).toBe(false);

    // (4) The reverse order, on a second home binding: the copy removed first, then protect-mcp. The id stays.
    const second = await homeBinding('vscode', path.join('.vscode', 'mcp.json'), 'linear');
    const w2 = dir('w2');
    const copy2 = write(path.join(w2, '.mcp.json'), { mcpServers: { linear: second.entry } });
    expect(await startFrom(w2, second.entry.args, 'vscode', 'linear')).toMatchObject({ starts: false, place: { refused: 'copy-found' } });
    fs.rmSync(copy2);
    await protectMcp({ projectDir: w2, wrapperPath: WRAPPER_PATH });
    expect((await vault().getBinding('vscode', 'linear'))?.id).toBe(second.id);
    expect(split(entryOf(second.file, 'linear').args).id).toBe(second.id);
  });
});
