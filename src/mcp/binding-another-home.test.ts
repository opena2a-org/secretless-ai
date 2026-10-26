import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { createBackend } from '../backends/factory';
import { runMcpStatus, runMcpUnprotect, runProtectMcp } from '../commands/mcp';
import { thisBuildWrapperPath } from './discover';
import { BindingHomeIdError } from './binding-home-id';
import { HOME_ID_UNUSABLE } from './protect';
import { bindingKey, openHomes, startWrapper } from './binding-homes.test-support';
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
