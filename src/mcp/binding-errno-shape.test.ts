import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { protectMcp } from './protect';
import { checkLaunchPlace } from './discover';
import { McpVault } from './vault';
import { createBackend } from '../backends/factory';
import { runMcpStatus } from '../commands/mcp';
import { MemoryStore } from './binding-store-double.test-support';

/**
 * A could-not line prints an error's code only where it is a string of the
 * errno shape, `^[A-Z][A-Z0-9_]{1,31}$`, and `unknown error` otherwise: the
 * code is read off whatever was thrown, so the printer keeps the line to
 * names. Errors are planted at the open of one project-level config, the one
 * call made for it; every other call reaches the real function.
 *
 * Every store is an in-memory double: no keychain, no network. Values are
 * assembled at run time and are not credentials.
 */

vi.mock('fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('fs')>();
  return { ...actual, openSync: vi.fn(actual.openSync) };
});

vi.mock('../backends/factory', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../backends/factory')>();
  return { ...actual, createBackend: vi.fn(actual.createBackend) };
});

const WRAPPER_PATH = path.resolve(__dirname, '..', '..', 'dist', 'mcp-wrapper.js');
const NAME = ['MY', 'SERVICE', 'API', 'KEY'].join('_');
const VALUE = ['stand', 'in', 'value', String(process.pid)].join('-');

let home: string;
let scratch: string;
let memory: MemoryStore;
let realOpen: typeof fs.openSync;
let saved: Record<'HOME' | 'USER', string | undefined>;

beforeEach(async () => {
  realOpen = (await vi.importActual<typeof import('fs')>('fs')).openSync;
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-errno-home-'));
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-errno-dirs-'));
  saved = { HOME: process.env.HOME, USER: process.env.USER };
  process.env.HOME = home;
  delete process.env.USER;
  write(path.join(home, '.secretless-ai', 'config.json'), { backend: 'local' });
  fs.mkdirSync(path.join(home, '.secretless-ai', 'mcp-vault'), { recursive: true });
  memory = new MemoryStore();
  vi.mocked(createBackend).mockImplementation(() => memory);
});

afterEach(() => {
  vi.mocked(fs.openSync).mockReset();
  vi.mocked(fs.openSync).mockImplementation(realOpen);
  vi.mocked(createBackend).mockReset();
  for (const [name, value] of Object.entries(saved)) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
  for (const d of [home, scratch]) fs.rmSync(d, { recursive: true, force: true });
});

function write(fullPath: string, content: unknown): string {
  fs.mkdirSync(path.dirname(fullPath), { recursive: true });
  fs.writeFileSync(fullPath, JSON.stringify(content, null, 2));
  return fullPath;
}

/** An error as a thrown value may carry one: a message, and a code of any shape. */
function planted(code: unknown): Error {
  return Object.assign(new Error('planted'), { code });
}

/** The open of `file`, by its real path, throws `err`; every other open is the real one. */
function plantAtOpen(file: string, err: Error): void {
  const target = fs.realpathSync(file);
  vi.mocked(fs.openSync).mockImplementation(((at: fs.PathLike, ...rest: unknown[]) => {
    if (String(at) === target) throw err;
    return (realOpen as (...args: unknown[]) => number)(at, ...rest);
  }) as typeof fs.openSync);
}

/** A home binding, and a project-level config in W the wrapper's check reads for its id. */
async function bindingAndConfig() {
  const file = write(path.join(home, '.cursor', 'mcp.json'), {
    mcpServers: { github: { command: process.execPath, args: ['-e', 'x'], env: { [NAME]: VALUE } } },
  });
  fs.mkdirSync(path.join(scratch, 'setup'));
  await protectMcp({ projectDir: path.join(scratch, 'setup'), wrapperPath: WRAPPER_PATH });
  const w = path.join(scratch, 'w');
  const config = write(path.join(w, '.cursor', 'mcp.json'), { mcpServers: {} });
  const record = await new McpVault({ backend: memory }).getBinding('cursor', 'github');
  expect(record?.scope).toBe('home');
  return { file, w, config, record: record! };
}

/** mcp-status run in `cwd`, in this process, with what it prints. */
async function status(cwd: string): Promise<string> {
  const lines: string[] = [];
  const log = vi.spyOn(console, 'log').mockImplementation((...parts: unknown[]) => { lines.push(parts.map(String).join(' ')); });
  const at = vi.spyOn(process, 'cwd').mockReturnValue(cwd);
  try {
    expect(await runMcpStatus()).toBe(0);
    return lines.join('\n');
  } finally {
    log.mockRestore();
    at.mockRestore();
  }
}

describe('X2-c: a could-not line prints an error code only of the errno shape', () => {
  it('a planted code of 32 hex characters: the check gives `unknown error`, and mcp-status prints `unknown error` and nothing of the code', async () => {
    const { w, config, record } = await bindingAndConfig();
    const code = crypto.randomBytes(16).toString('hex');
    expect(code).toMatch(/^[0-9a-f]{32}$/);
    plantAtOpen(config, planted(code));

    const verdict = checkLaunchPlace(record, { startDir: w, home });
    expect(verdict).toEqual({ refused: 'copy-unchecked', file: path.join(fs.realpathSync(w), '.cursor', 'mcp.json'), why: 'it could not be read (unknown error)' });

    const output = await status(w);
    expect(output).toContain(
      `    ? github: protected and bound, but ${path.join(fs.realpathSync(w), '.cursor', 'mcp.json')} could not be checked for a copy of its binding `
        + '(it could not be read (unknown error)), so the wrapper does not start it\n',
    );
    expect(output.includes(code), 'the planted code is printed').toBe(false);
  });

  it('a planted EACCES: the check gives EACCES, and mcp-status prints it', async () => {
    const { w, config, record } = await bindingAndConfig();
    plantAtOpen(config, planted('EACCES'));

    expect(checkLaunchPlace(record, { startDir: w, home })).toMatchObject({ refused: 'copy-unchecked', why: 'it could not be read (EACCES)' });
    expect(await status(w)).toContain('could not be checked for a copy of its binding (it could not be read (EACCES)), so the wrapper does not start it\n');
  });

  const shapes: Array<[string, unknown, string]> = [
    ['a lowercase code', 'eacces', 'unknown error'],
    ['one character', 'E', 'unknown error'],
    ['33 characters', `E${'A'.repeat(32)}`, 'unknown error'],
    ['32 characters', `E${'A'.repeat(31)}`, `E${'A'.repeat(31)}`],
    ['a code with a space', 'EACCES 1', 'unknown error'],
    ['a number', 13, 'unknown error'],
    ['no code', undefined, 'unknown error'],
  ];
  it.each(shapes)('%s (%s): the check gives %s', async (_label, code, printed) => {
    const { w, config, record } = await bindingAndConfig();
    plantAtOpen(config, planted(code));
    expect(checkLaunchPlace(record, { startDir: w, home })).toMatchObject({ refused: 'copy-unchecked', why: `it could not be read (${printed})` });
  });
});
