import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { createBackend } from '../backends/factory';
import { LEFT_ANOTHER_MACHINE, LEFT_CHANGED, runMcpStatus, runMcpUnprotect, runProtectMcp } from '../commands/mcp';
import { listedName } from '../secret-value';
import { thisBuildWrapperPath } from './discover';
import { ANOTHER_MACHINE_CLAUSE, ANOTHER_MACHINE_REASON, BINDING_NOT_AS_READ, HOME_ID_UNUSABLE, storeBindingOf } from './protect';
import { BindingWriteRefusedError, McpVault } from './vault';
import type { McpBinding } from './vault';
import { bindingKey, openHomes, sha256, startWrapper } from './binding-homes.test-support';
import type { HomeName, Homes } from './binding-homes.test-support';

/**
 * Cells T10: a binding's writer identity (McpBinding.boundOn) on a store
 * several machines read.
 *
 * Two secretless homes, A and B, are swapped into one HOME path between runs
 * (binding-homes.test-support.ts): two machines whose home and project
 * directories are equal paths. The store is a double that reports the
 * backend it stands in for and keeps its entries in a file outside HOME, so
 * protect-mcp, mcp-status and mcp-unprotect, run in this process as the CLI
 * runs them, and the built wrapper, started as a child, read one store. No
 * other backend is built: a cell that asks for one fails. Values are made at
 * run time and are not credentials.
 */

vi.mock('../backends/factory', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../backends/factory')>();
  return { ...actual, createBackend: vi.fn(actual.createBackend) };
});

const NAME = ['MY', 'SERVICE', 'API', 'KEY'].join('_');
const VALUE = ['stand', 'in', 'value', String(process.pid)].join('-');

/** Every output of the wrapper, protect-mcp, mcp-status and mcp-unprotect in this file, and every home id made (cell (k)). */
const outputs: Array<{ source: string; text: string }> = [];
const madeIds: string[] = [];

let homes: Homes | undefined;
let saved: Record<'HOME' | 'USER' | 'PATH', string | undefined>;

beforeEach(() => {
  saved = { HOME: process.env.HOME, USER: process.env.USER, PATH: process.env.PATH };
});

afterEach(() => {
  vi.mocked(createBackend).mockReset();
  for (const [name, value] of Object.entries(saved)) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
  homes?.close();
  homes = undefined;
});

/** The two homes of a cell, with A in HOME, and the store double as the only backend this process builds. */
function open(backend = '1password', options: { withoutId?: HomeName[] } = {}): Homes {
  const made = openHomes(backend, options);
  homes = made;
  madeIds.push(made.ids.A, made.ids.B);
  process.env.HOME = made.home;
  delete process.env.USER;
  process.env.PATH = `${made.bin}${path.delimiter}${saved.PATH ?? ''}`;
  vi.mocked(createBackend).mockImplementation((type) => {
    if (type === made.store.name) return made.store;
    throw new Error(`this cell builds only its store double, not ${type}`);
  });
  return made;
}

/** The homes of the cell running. */
function h(): Homes {
  if (homes === undefined) throw new Error('no homes open');
  return homes;
}

type Command = 'protect-mcp' | 'mcp-status' | 'mcp-unprotect';

/** A command of the CLI in this process, from `cwd` (D by default), in the home now in HOME: what it prints. */
async function cli(command: Command, cwd = h().project): Promise<string> {
  const lines: string[] = [];
  const capture = (...parts: unknown[]) => { lines.push(parts.map(String).join(' ')); };
  const log = vi.spyOn(console, 'log').mockImplementation(capture);
  const error = vi.spyOn(console, 'error').mockImplementation(capture);
  const dir = vi.spyOn(process, 'cwd').mockReturnValue(cwd);
  try {
    if (command === 'protect-mcp') await runProtectMcp([]);
    else if (command === 'mcp-status') await runMcpStatus();
    else await runMcpUnprotect();
  } finally {
    log.mockRestore();
    error.mockRestore();
    dir.mockRestore();
  }
  const text = lines.join('\n');
  outputs.push({ source: command, text });
  return text;
}

/** The built wrapper started with an entry's args from `cwd`, in the home now in HOME. */
function wrapper(args: readonly string[], cwd = h().project): { status: number | null; output: string } {
  const run = startWrapper(h(), args, cwd);
  outputs.push({ source: 'wrapper', text: run.output });
  return run;
}

/** The wrapper path protect-mcp writes into a config in this process. */
const WRAPPER = thisBuildWrapperPath();

const projectConfig = () => path.join(h().project, '.mcp.json');
const homeConfig = () => path.join(h().home, '.cursor', 'mcp.json');

function write(file: string, servers: Record<string, unknown>): string {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify({ mcpServers: servers }, null, 2));
  return file;
}

/** The entry `name` of a config file, as the file now holds it. */
function entryOf(file: string, name: string): { command: string; args: string[]; env?: Record<string, string> } {
  return JSON.parse(fs.readFileSync(file, 'utf-8')).mcpServers[name];
}

/** A stub server that leaves `sentinel` when it starts. */
const stubArgs = (sentinel: string): string[] =>
  ['-e', `require('fs').writeFileSync(${JSON.stringify(sentinel)}, 'started')`];

/** A server with a secret in its env, as protect-mcp first finds it. */
const plain = (sentinel = path.join(h().root, 'started')) => ({ command: process.execPath, args: stubArgs(sentinel), env: { [NAME]: VALUE } });

/** A server that runs through the wrapper reading `client/server`, with no --binding, as an earlier version wrote it. */
const wrappedUnbound = (client: string, server: string) => ({
  command: WRAPPER,
  args: ['--server', server, '--client', client, '--', process.execPath, '-e', 'x'],
  env: {},
});

/** The text stored as a pair's binding. */
const recordText = (client: string, server: string): string | undefined => h().store.raw(bindingKey(client, server));

/** The names stored under a pair, as the store holds them. */
const storedNames = (client: string, server: string): string[] =>
  Object.keys(h().store.all()).filter((key) => key.startsWith(`mcp/${client}/${server}/`));

const hex = (bytes: number) => crypto.randomBytes(bytes).toString('hex');

/** A config entry as a file holds it. */
type Entry = { command: string; args: string[]; env?: Record<string, string> };

/** Put `entry` as server `name` of a config file, leaving its other servers. */
function setEntry(file: string, name: string, entry: Entry): void {
  const raw = JSON.parse(fs.readFileSync(file, 'utf-8'));
  raw.mcpServers[name] = entry;
  fs.writeFileSync(file, JSON.stringify(raw, null, 2));
}

/** Wrapper args without the --binding before the wrapper's own `--`: an entry that carries no id. */
function withoutId(args: readonly string[]): string[] {
  const end = args.indexOf('--');
  const at = args.indexOf('--binding');
  if (at === -1 || (end !== -1 && at > end)) return [...args];
  return [...args.slice(0, at), ...args.slice(at + 2)];
}

/** Wrapper args with another command after the wrapper's own `--`. */
function withChild(args: readonly string[], child: readonly string[]): string[] {
  return [...args.slice(0, args.indexOf('--') + 1), ...child];
}

/** The binding stored for a pair, parsed, or undefined. */
function recordOf(client: string, server: string): Record<string, unknown> | undefined {
  const text = recordText(client, server);
  return text === undefined ? undefined : JSON.parse(text);
}

/**
 * A binds server `s` in `file` (the project's .mcp.json, client
 * claude-code, or the home cursor config, client cursor): the server with a
 * secret in its env, protected by protect-mcp run from D with A in HOME. The
 * entry it wrote, and the binding as stored, which names that entry. That
 * the binding carries A's id is cell (J1)'s: the setup asks only that the
 * binding was stored, so a build that stores none fails a cell on what it
 * then does.
 */
async function bindInA(file: string, client: string): Promise<{ entry: Entry; record: Record<string, unknown>; text: string }> {
  h().use('A');
  write(file, { s: plain(path.join(h().root, 's-started')) });
  await cli('protect-mcp');
  const text = recordText(client, 's');
  expect(text).toBeDefined();
  const record = JSON.parse(text!);
  expect(record).toMatchObject({ file, server: 's' });
  return { entry: entryOf(file, 's'), record, text: text! };
}

/**
 * Hand the home `to` a copy of the backups of the home now in HOME, and move
 * it into HOME: the backup of a file at a path both homes share, so the
 * home `to` restores that file as the other one would.
 */
function carryBackupsTo(to: HomeName): void {
  const held = path.join(h().root, `backups-for-${to}`);
  fs.cpSync(path.join(h().dataDir(), 'mcp-backups'), held, { recursive: true });
  h().use(to);
  fs.rmSync(path.join(h().dataDir(), 'mcp-backups'), { recursive: true, force: true });
  fs.cpSync(held, path.join(h().dataDir(), 'mcp-backups'), { recursive: true });
}

/** The setups of cells (a) to (e) and (m), run in the home now in HOME after A bound: protect-mcp from D, and what it printed. */
const setups = {
  /** (a) the project config's entry at its place, carrying no id. */
  a: async (entry: Entry) => {
    setEntry(projectConfig(), 's', { ...entry, args: withoutId(entry.args) });
    return cli('protect-mcp');
  },
  /** (c) R6: the home entry carries A's id, and its child command differs. */
  c: async (entry: Entry) => {
    setEntry(homeConfig(), 's', { ...entry, args: withChild(entry.args, [process.execPath, '-e', 'y']) });
    return cli('protect-mcp');
  },
  /** (d) R6a: the home entry at its place, carrying no id. */
  d: async (entry: Entry) => {
    setEntry(homeConfig(), 's', { ...entry, args: withoutId(entry.args) });
    return cli('protect-mcp');
  },
  /** (m) the unwrapped store point: the home entry at its place, not wrapped, holding the values stored. */
  m: async () => {
    setEntry(homeConfig(), 's', plain(path.join(h().root, 's-started')));
    return cli('protect-mcp');
  },
  /** (b) R8: B's D/.mcp.json holds no server s, and a candidate, t, reads the pair. */
  b: async (entry: Entry) => {
    write(projectConfig(), { t: { command: entry.command, args: ['--server', 's', '--client', 'claude-code', '--', process.execPath, '-e', 'x'], env: {} } });
    return cli('protect-mcp');
  },
  /** (e) S3: a copy of the home entry, carrying A's id, in D/.mcp.json, which protect-mcp rewrites; the home entry is at its place. */
  e: async (entry: Entry) => {
    write(projectConfig(), { s: { ...entry } });
    return cli('protect-mcp');
  },
  /** (e) through the S3 trigger: the copy in D/.cursor/mcp.json, which the wrapper's start check reads and protect-mcp does not rewrite. */
  eS2: async (entry: Entry) => {
    write(path.join(h().project, '.cursor', 'mcp.json'), { s: { ...entry } });
    return cli('protect-mcp');
  },
  /** (f) R9: mcp-unprotect from D restores D/.mcp.json, which holds the values stored, from the backups of the home now in HOME. */
  f: async () => cli('mcp-unprotect'),
};

/** The line mcp-unprotect prints for a pair it deletes, as built. */
const DELETED = (client: string, server: string, count: number): string =>
  `  - Deleted from the store: ${listedName(`${client}/${server}`)} (${count} name(s); the restored file holds the same values)`;

describe('(a) a binding another home stored is left as it is', () => {
  it('A binds server s in D\'s project config; B runs protect-mcp in D, whose entry carries no id: left with the another-machine reason, and the record\'s bytes are equal', async () => {
    open();
    const { entry, text } = await bindInA(projectConfig(), 'claude-code');
    h().use('B');

    const output = await setups.a(entry);

    expect(sha256(recordText('claude-code', 's'))).toBe(sha256(text));
    expect(h().store.bindingWrites).toHaveLength(1);
    expect(output).toContain(`    ? s: not bound: ${ANOTHER_MACHINE_REASON({ client: 'claude-code', server: 's' })}`);
  });
});

describe('(c) R6: a binding another home stored is not bound again with a changed command', () => {
  it('B\'s home entry carries A\'s id and its child command differs: no rebind, and commandDigest is unchanged', async () => {
    open();
    const { entry, record, text } = await bindInA(homeConfig(), 'cursor');
    h().use('B');

    const output = await setups.c(entry);

    expect(recordOf('cursor', 's')!.commandDigest).toBe(record.commandDigest);
    expect(sha256(recordText('cursor', 's'))).toBe(sha256(text));
    expect(output).toContain(`    ? s: not bound: ${ANOTHER_MACHINE_REASON({ client: 'cursor', server: 's' })}`);
  });
});

describe('(d) R6a: another home\'s id is not written into this home\'s entry', () => {
  it('B\'s home entry is at the equal path and carries no id: no stale, and the entry\'s bytes are unchanged', async () => {
    open();
    const { entry, text } = await bindInA(homeConfig(), 'cursor');
    h().use('B');
    setEntry(homeConfig(), 's', { ...entry, args: withoutId(entry.args) });
    const before = fs.readFileSync(homeConfig(), 'utf-8');

    const output = await cli('protect-mcp');

    expect(fs.readFileSync(homeConfig(), 'utf-8')).toBe(before);
    expect(sha256(recordText('cursor', 's'))).toBe(sha256(text));
    expect(output).toContain(`    ? s: not bound: ${ANOTHER_MACHINE_REASON({ client: 'cursor', server: 's' })}`);
  });
});

describe('(g) the same setups with A swapped back in act as built: the interlock is what stopped them', () => {
  it('(c) with A: the binding takes the changed command (re-digest)', async () => {
    open();
    const { entry, record } = await bindInA(homeConfig(), 'cursor');
    h().use('B');
    h().use('A');

    const output = await setups.c(entry);

    expect(output).toContain('    ~ s: its command or arguments changed since it was bound; bound again');
    expect(recordOf('cursor', 's')).toMatchObject({ id: record.id, boundOn: h().ids.A });
    expect(recordOf('cursor', 's')!.commandDigest).not.toBe(record.commandDigest);
  });

  it('(d) with A: the binding\'s id is written into the entry again', async () => {
    open();
    const { entry, record } = await bindInA(homeConfig(), 'cursor');
    h().use('B');
    h().use('A');

    const output = await setups.d(entry);

    expect(output).toContain('    ~ s: it did not carry the binding stored for it; bound again\n');
    expect(entryOf(homeConfig(), 's').args).toEqual(entry.args);
    expect(recordOf('cursor', 's')!.id).toBe(record.id);
  });
});

describe('(i) a binding with no boundOn, as an earlier version stored it', () => {
  /** A's binding of the home entry, stored again without its boundOn. */
  async function earlierBinding(): Promise<{ entry: Entry; record: Record<string, unknown> }> {
    const { entry, record } = await bindInA(homeConfig(), 'cursor');
    const { boundOn: _boundOn, ...earlier } = record;
    h().store.put(bindingKey('cursor', 's'), JSON.stringify(earlier));
    return { entry, record: earlier };
  }

  it('on 1password: no home owns it, the one whose protect-mcp wrote it included, and nothing is written', async () => {
    open();
    const { entry } = await earlierBinding();
    const before = recordText('cursor', 's');

    const output = await setups.c(entry);

    expect(recordText('cursor', 's')).toBe(before);
    expect(h().store.bindingWrites).toHaveLength(1);
    expect(output).toContain(`    ? s: not bound: ${ANOTHER_MACHINE_REASON({ client: 'cursor', server: 's' })}`);
  });

  it('on local: it is this machine\'s, and protect-mcp binds it again, now with this home\'s id', async () => {
    open('local');
    const { entry, record } = await earlierBinding();

    const output = await setups.c(entry);

    expect(output).toContain('    ~ s: its command or arguments changed since it was bound; bound again');
    expect(recordOf('cursor', 's')).toMatchObject({ id: record.id, boundOn: h().ids.A });
  });
});

describe('(m) the unwrapped store point: a binding another home stored is not written over', () => {
  it('B\'s unwrapped entry is at the equal path and holds the values stored: left with the another-machine reason, and the record\'s bytes are unchanged', async () => {
    open();
    const { text } = await bindInA(homeConfig(), 'cursor');
    h().use('B');

    const output = await setups.m();

    expect(sha256(recordText('cursor', 's'))).toBe(sha256(text));
    expect(h().store.bindingWrites).toHaveLength(1);
    expect(output).toContain(`    ? s: not protected: ${ANOTHER_MACHINE_REASON({ client: 'cursor', server: 's' })}`);
  });
});

describe('(n) the funnel: a binding this home did not store is never written over or deleted', () => {
  const reads = { client: 'cursor', server: 's' };

  /** A binding of cursor/s, to the home cursor config's entry, as the home whose id is `boundOn` stores it. */
  const recordFor = (boundOn: string): McpBinding => ({
    schema: 1,
    id: hex(16),
    scope: 'home',
    file: homeConfig(),
    client: 'cursor',
    server: 's',
    commandDigest: `sha256:${hex(32)}`,
    boundAt: new Date().toISOString(),
    boundBy: 'cell',
    boundOn,
  });

  /** What storeBindingOf takes: the store double, and the home in HOME with its id. */
  const binder = () => ({
    vault: new McpVault({ backend: h().store }),
    bindings: new Map<string, McpBinding | undefined>(),
    home: { dir: h().dataDir(), id: h().ids[h().current()] },
  });

  it('storeBindingOf over a binding another home stored: refused, and nothing is written; over one this home stored: written', async () => {
    open();
    const theirs = recordFor(h().ids.B);
    h().store.put(bindingKey('cursor', 's'), JSON.stringify(theirs));

    const refused = storeBindingOf(binder(), reads, { ...theirs, id: hex(16) }, theirs);

    await expect(refused).rejects.toBeInstanceOf(BindingWriteRefusedError);
    await expect(refused).rejects.toMatchObject({ why: 'not-owned' });
    expect(h().store.bindingWrites).toEqual([]);
    expect(recordText('cursor', 's')).toBe(JSON.stringify(theirs));

    const ours = recordFor(h().ids.A);
    h().store.put(bindingKey('cursor', 's'), JSON.stringify(ours));
    const next = { ...ours, id: hex(16) };

    const stored = await storeBindingOf(binder(), reads, next, ours);

    expect(stored).toEqual({ ...next, boundOn: h().ids.A });
    expect(recordOf('cursor', 's')).toEqual({ ...next, boundOn: h().ids.A });
    expect(h().store.bindingWrites).toHaveLength(1);
  });

  it('storeBindingOf where the binding stored is not the one its plan read, or its plan read none: refused, and nothing is written', async () => {
    open();
    const ours = recordFor(h().ids.A);
    h().store.put(bindingKey('cursor', 's'), JSON.stringify(ours));

    const read = { ...ours, commandDigest: `sha256:${hex(32)}` };
    await expect(storeBindingOf(binder(), reads, recordFor(h().ids.A), read)).rejects.toMatchObject({ why: 'changed' });
    await expect(storeBindingOf(binder(), reads, recordFor(h().ids.A), undefined)).rejects.toMatchObject({ why: 'changed' });

    expect(h().store.bindingWrites).toEqual([]);
    expect(recordText('cursor', 's')).toBe(JSON.stringify(ours));
  });

  it('on a store that is this machine\'s alone, storeBindingOf writes over a binding with another home\'s id', async () => {
    open('local');
    const theirs = recordFor(h().ids.B);
    h().store.put(bindingKey('cursor', 's'), JSON.stringify(theirs));
    const next = { ...theirs, id: hex(16) };

    await storeBindingOf(binder(), reads, next, theirs);

    expect(recordOf('cursor', 's')).toEqual({ ...next, boundOn: h().ids.A });
  });

  it('removeOwnedPair over a pair another home bound: refused, and its names and binding stay; over one this home bound: deleted', async () => {
    open();
    const vault = new McpVault({ backend: h().store });
    const theirs = recordFor(h().ids.B);
    h().store.put(bindingKey('cursor', 's'), JSON.stringify(theirs));
    h().store.put(`mcp/cursor/s/${NAME}`, VALUE);

    await expect(vault.removeOwnedPair('cursor', 's', theirs, h().ids.A)).rejects.toMatchObject({ why: 'not-owned' });
    expect(storedNames('cursor', 's')).toEqual([`mcp/cursor/s/${NAME}`]);
    expect(recordText('cursor', 's')).toBe(JSON.stringify(theirs));

    const ours = recordFor(h().ids.A);
    h().store.put(bindingKey('cursor', 's'), JSON.stringify(ours));
    await expect(vault.removeOwnedPair('cursor', 's', theirs, h().ids.A)).rejects.toMatchObject({ why: 'changed' });
    expect(recordText('cursor', 's')).toBe(JSON.stringify(ours));

    await vault.removeOwnedPair('cursor', 's', ours, h().ids.A);

    expect(storedNames('cursor', 's')).toEqual([]);
    expect(recordText('cursor', 's')).toBeUndefined();
  });

  /**
   * After the first read of the binding of `client/server` in the run that
   * follows, the store holds `changed` in its place: the binding changes
   * between the run's read and its write.
   */
  function changeAfterFirstRead(client: string, server: string, changed: Record<string, unknown>): void {
    const store = h().store;
    const resolve = store.resolve.bind(store);
    let first = true;
    vi.spyOn(store, 'resolve').mockImplementation(async (at, options) => {
      const found = await resolve(at, options);
      if (first && at === bindingKey(client, server) && options?.exact) {
        first = false;
        store.put(bindingKey(client, server), JSON.stringify(changed));
      }
      return found;
    });
  }

  it('through protect-mcp: a binding that changed after the run read it is not written over, and the line says so', async () => {
    open();
    const { entry, record } = await bindInA(homeConfig(), 'cursor');
    const changed = { ...record, boundAt: new Date(0).toISOString() };
    changeAfterFirstRead('cursor', 's', changed);

    const output = await setups.c(entry);

    expect(recordText('cursor', 's')).toBe(JSON.stringify(changed));
    expect(h().store.bindingWrites).toHaveLength(1);
    expect(output).toContain(`    ? s: not bound: ${BINDING_NOT_AS_READ(new BindingWriteRefusedError('cursor', 's', 'changed'))}`);
  });

  it('through mcp-unprotect: a pair whose binding changed after the run read it is not deleted, and the line says so', async () => {
    open();
    const { record } = await bindInA(projectConfig(), 'claude-code');
    const changed = { ...record, boundAt: new Date(0).toISOString() };
    changeAfterFirstRead('claude-code', 's', changed);

    const output = await setups.f();

    expect(storedNames('claude-code', 's')).toEqual([`mcp/claude-code/s/${NAME}`]);
    expect(recordText('claude-code', 's')).toBe(JSON.stringify(changed));
    expect(output).toContain(LEFT_CHANGED(listedName('claude-code/s'), [NAME]));
  });
});

describe('(b) R8: a binding another home stored is not taken over', () => {
  it('B\'s D/.mcp.json holds no server s, and a candidate there reads the pair: no takeover, and the record is unchanged', async () => {
    open();
    const { entry, text } = await bindInA(projectConfig(), 'claude-code');
    h().use('B');

    const output = await setups.b(entry);

    expect(sha256(recordText('claude-code', 's'))).toBe(sha256(text));
    expect(output).not.toContain('took over');
    expect(h().store.bindingWrites).toHaveLength(1);
    expect(h().tripped()).toEqual([]);
  });
});

describe('(e) S3: a binding another home stored is not replaced', () => {
  it('B holds a copy carrying A\'s id in D/.mcp.json, and B\'s home entry is at the equal path: no replace, and the record\'s id is unchanged', async () => {
    open();
    const { entry, record, text } = await bindInA(homeConfig(), 'cursor');
    h().use('B');

    const output = await setups.e(entry);

    expect(recordOf('cursor', 's')!.id).toBe(record.id);
    expect(sha256(recordText('cursor', 's'))).toBe(sha256(text));
    expect(entryOf(homeConfig(), 's')).toEqual(entry);
    expect(output).not.toContain('the binding was replaced');
    expect(h().store.bindingWrites).toHaveLength(1);
  });

  it('through the S3 trigger: the copy is in D/.cursor/mcp.json, which the wrapper\'s start check reads and protect-mcp does not rewrite: no replace, and the record\'s id is unchanged', async () => {
    open();
    const { entry, record, text } = await bindInA(homeConfig(), 'cursor');
    h().use('B');

    const output = await setups.eS2(entry);

    expect(recordOf('cursor', 's')!.id).toBe(record.id);
    expect(sha256(recordText('cursor', 's'))).toBe(sha256(text));
    expect(entryOf(homeConfig(), 's')).toEqual(entry);
    expect(output).not.toContain('the binding was replaced');
    expect(h().store.bindingWrites).toHaveLength(1);
  });
});

describe('(f) R9: a pair another home bound is not deleted', () => {
  it('B\'s mcp-unprotect restores its own D/.mcp.json, which holds the values stored: the pair\'s names and the record are still in the store', async () => {
    open();
    const { text } = await bindInA(projectConfig(), 'claude-code');
    carryBackupsTo('B');

    const output = await setups.f();

    expect(storedNames('claude-code', 's')).toEqual([`mcp/claude-code/s/${NAME}`]);
    expect(sha256(recordText('claude-code', 's'))).toBe(sha256(text));
    expect(entryOf(projectConfig(), 's')).toEqual(plain(path.join(h().root, 's-started')));
    expect(output).toContain(LEFT_ANOTHER_MACHINE(listedName('claude-code/s'), [NAME]));
    expect(output).not.toContain('Deleted from the store');
  });
});

describe('(g) (f) with A swapped back in acts as built: the interlock is what stopped it', () => {
  it('(f) with A: A\'s mcp-unprotect deletes the pair\'s names and its binding', async () => {
    open();
    await bindInA(projectConfig(), 'claude-code');
    h().use('B');
    h().use('A');

    const output = await setups.f();

    expect(output).toContain(DELETED('claude-code', 's', 1));
    expect(storedNames('claude-code', 's')).toEqual([]);
    expect(recordText('claude-code', 's')).toBeUndefined();
  });
});

describe('(h) on a store that is this machine\'s alone, each acts as built, whatever binding-home-id holds and when it is absent', () => {
  for (const id of ['B\'s own', 'absent'] as const) {
    const homeOptions = id === 'absent' ? { withoutId: ['B' as const] } : {};

    it(`(a) with B's id ${id}: the project config's entry is left as built, and the record's bytes are equal`, async () => {
      open('local', homeOptions);
      const { entry, text } = await bindInA(projectConfig(), 'claude-code');
      h().use('B');

      const output = await setups.a(entry);

      expect(sha256(recordText('claude-code', 's'))).toBe(sha256(text));
      expect(output).toContain('    ? s: not bound: its binding does not match the one stored for claude-code/s.');
      expect(output).not.toContain(ANOTHER_MACHINE_REASON({ client: 'claude-code', server: 's' }));
    });

    it(`(c) with B's id ${id}: the binding takes the changed command (re-digest)`, async () => {
      open('local', homeOptions);
      const { entry, record } = await bindInA(homeConfig(), 'cursor');
      h().use('B');

      const output = await setups.c(entry);

      expect(output).toContain('    ~ s: its command or arguments changed since it was bound; bound again');
      expect(recordOf('cursor', 's')!.id).toBe(record.id);
      expect(recordOf('cursor', 's')!.commandDigest).not.toBe(record.commandDigest);
    });

    it(`(d) with B's id ${id}: the binding's id is written into the entry again`, async () => {
      open('local', homeOptions);
      const { entry, record } = await bindInA(homeConfig(), 'cursor');
      h().use('B');

      const output = await setups.d(entry);

      expect(output).toContain('    ~ s: it did not carry the binding stored for it; bound again\n');
      expect(entryOf(homeConfig(), 's').args).toEqual(entry.args);
      expect(recordOf('cursor', 's')!.id).toBe(record.id);
    });

    it(`(f) with B's id ${id}: B's mcp-unprotect deletes the pair's names and its binding`, async () => {
      open('local', homeOptions);
      await bindInA(projectConfig(), 'claude-code');
      carryBackupsTo('B');

      const output = await setups.f();

      expect(output).toContain(DELETED('claude-code', 's', 1));
      expect(storedNames('claude-code', 's')).toEqual([]);
      expect(recordText('claude-code', 's')).toBeUndefined();
    });

    it(`(m) with B's id ${id}: the unwrapped entry is bound again in place, over the binding stored`, async () => {
      open('local', homeOptions);
      const { record } = await bindInA(homeConfig(), 'cursor');
      h().use('B');

      const output = await setups.m();

      expect(h().store.bindingWrites).toHaveLength(2);
      expect(recordOf('cursor', 's')).toMatchObject({ file: homeConfig(), server: 's' });
      expect(recordOf('cursor', 's')!.id).not.toBe(record.id);
      expect(entryOf(homeConfig(), 's').command).toBe(WRAPPER);
      expect(output).not.toContain(ANOTHER_MACHINE_REASON({ client: 'cursor', server: 's' }));
    });

    it(`(b) with B's id ${id}: the candidate takes the binding over`, async () => {
      open('local', homeOptions);
      const { entry } = await bindInA(projectConfig(), 'claude-code');
      h().use('B');

      const output = await setups.b(entry);

      expect(output).toContain('took over the binding of server "s"');
      expect(recordOf('claude-code', 's')).toMatchObject({ server: 't', file: projectConfig() });
    });

    it(`(e) with B's id ${id}: the binding is replaced`, async () => {
      open('local', homeOptions);
      const { entry, record } = await bindInA(homeConfig(), 'cursor');
      h().use('B');

      const output = await setups.e(entry);

      expect(output).toContain('the binding was replaced');
      expect(recordOf('cursor', 's')!.id).not.toBe(record.id);
    });

    it(`(e) through the S3 trigger with B's id ${id}: the binding is replaced`, async () => {
      open('local', homeOptions);
      const { entry, record } = await bindInA(homeConfig(), 'cursor');
      h().use('B');

      const output = await setups.eS2(entry);

      expect(output).toContain('the binding was replaced, so the copy no longer starts');
      expect(recordOf('cursor', 's')!.id).not.toBe(record.id);
    });
  }
});

describe('(J5) the another-machine words carry what the ruling fixes, pending their final words', () => {
  const reads = { client: 'claude-code', server: 's' };

  it('the reason names the pair, another secretless home on another machine or this one before its ~/.secretless-ai was replaced, that this machine leaves the binding, and a new name with its own values', () => {
    const reason = ANOTHER_MACHINE_REASON(reads);
    expect(reason).toContain('claude-code/s');
    expect(reason).toContain('protect-mcp in another secretless home');
    expect(reason).toContain('on another machine');
    expect(reason).toContain('before its ~/.secretless-ai was replaced');
    expect(reason).toContain('protect-mcp and mcp-unprotect on this machine leave that binding as it is');
    expect(reason).toContain('under a new name with its own values');
  });

  it('the clause names the file as a path on that machine, and says this machine leaves the binding', () => {
    const file = path.join(path.sep, 'elsewhere', '.cursor', 'mcp.json');
    const clause = ANOTHER_MACHINE_CLAUSE(file);
    expect(clause).toContain(`${file} is a path there`);
    expect(clause).toContain('protect-mcp in another secretless home');
    expect(clause).toContain('protect-mcp and mcp-unprotect on this machine leave that binding as it is');
  });

  it('neither says the entry no longer exists, nor names a command that deletes a binding', () => {
    for (const words of [ANOTHER_MACHINE_REASON(reads), ANOTHER_MACHINE_CLAUSE('/f')]) {
      expect(words).not.toContain('no longer exists');
      expect(words).not.toContain('mcp-forget');
      expect(words).not.toMatch(/\bforget\b|\bdelete\b/);
    }
  });
});

describe('(J1) every binding protect-mcp stores names the secretless home that stored it', () => {
  it('a server moved into the store and a wrapped entry bound in place both carry the home\'s id as boundOn', async () => {
    open();
    write(projectConfig(), { s: plain() });
    write(homeConfig(), { t: wrappedUnbound('cursor', 't') });

    await cli('protect-mcp');

    expect(JSON.parse(recordText('claude-code', 's')!).boundOn).toBe(h().ids.A);
    expect(JSON.parse(recordText('cursor', 't')!).boundOn).toBe(h().ids.A);
    expect(h().store.bindingWrites.map((write) => JSON.parse(write.value).boundOn)).toEqual([h().ids.A, h().ids.A]);
  });

  it('the bindings the cells\' setup stores, in the project config and in the home cursor config, carry A\'s id', async () => {
    open();
    const project = await bindInA(projectConfig(), 'claude-code');
    const home = await bindInA(homeConfig(), 'cursor');

    expect(project.record.boundOn).toBe(h().ids.A);
    expect(home.record.boundOn).toBe(h().ids.A);
  });
});

describe('(j) the home id file', () => {
  it('absent: protect-mcp creates it with mode 0600 and 32 hex digits when it stores a binding', async () => {
    open('1password', { withoutId: ['A'] });
    expect(fs.existsSync(h().idFile())).toBe(false);
    write(projectConfig(), { s: plain() });

    await cli('protect-mcp');

    expect(recordText('claude-code', 's')).toBeDefined();
    expect(fs.statSync(h().idFile()).mode & 0o777).toBe(0o600);
    const held = fs.readFileSync(h().idFile(), 'latin1');
    expect(held).toMatch(/^[0-9a-f]{32}\n?$/);
    expect(JSON.parse(recordText('claude-code', 's')!).boundOn).toBe(held.trim());
  });

  it('malformed: no binding is stored, each entry it would bind is left with the error, and the file is unchanged', async () => {
    open();
    const held = hex(16).toUpperCase();
    fs.writeFileSync(h().idFile(), held);
    write(projectConfig(), { s: plain() });
    write(homeConfig(), { t: wrappedUnbound('cursor', 't') });
    const { BindingHomeIdError } = await import('./binding-home-id.js');
    const reason = HOME_ID_UNUSABLE(new BindingHomeIdError(h().idFile(), { kind: 'malformed' }));

    const output = await cli('protect-mcp');

    expect(output).toContain(`    ? s: secrets not moved: ${reason}`);
    expect(output).toContain(`    ? t: not bound: ${reason}`);
    expect(output).not.toContain(held);
    expect(h().store.bindingWrites).toEqual([]);
    expect(Object.keys(h().store.all())).toEqual([]);
    expect(fs.readFileSync(h().idFile(), 'latin1')).toBe(held);
    expect(entryOf(projectConfig(), 's')).toEqual(plain());

    // mcp-status names what protect-mcp then does: it leaves the entry with the same error.
    const status = await cli('mcp-status');
    expect(status).toContain(`protect-mcp\` leaves it not bound: ${reason}`);
    expect(fs.readFileSync(h().idFile(), 'latin1')).toBe(held);
    expect(h().tripped()).toEqual([]);
  });
});
