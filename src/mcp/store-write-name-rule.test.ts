import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { protectMcp } from './protect';
import { McpVault, commandDigest, mcpNameProblem, newBindingId } from './vault';
import type { McpBinding } from './vault';
import { rewriteConfig } from './rewrite';
import { createBackend } from '../backends/factory';
import type { ResolveOptions, WritableSecretBackend } from '../backends/types';

/**
 * The store writes a pair only under a client and server name its write rule,
 * mcpNameProblem, takes: not empty, only A-Z, a-z, 0-9, - and _, and not
 * beginning with -. A read or a delete applies the character class only, so
 * a pair an earlier version stored under a name that begins with - stays
 * readable by its wrapper and removable. protect-mcp leaves a server whose
 * name the rule refuses as it is, with the reason, and the config rewrite
 * applies the same rule.
 *
 * protect-mcp runs in this process with no home directory given, HOME set to
 * a scratch directory and the local backend configured, so its store is the
 * encrypted file under ~/.secretless-ai/mcp-vault. Values are assembled at
 * run time and are not credentials.
 */

const WRAPPER_PATH = path.resolve(__dirname, '..', '..', 'dist', 'mcp-wrapper.js');
const NAME = ['MY', 'SERVICE', 'API', 'KEY'].join('_');
const VALUE = ['stand', 'in', 'value', String(process.pid)].join('-');
/** The write rule's reason for a name whose first character is -. */
const LEADING_DASH = 'it begins with -, which a command line reads as an option';
const CLASS = 'it holds a character other than A-Z, a-z, 0-9, - or _';

let home: string;
let project: string;
let saved: Record<'HOME' | 'USER', string | undefined>;

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-name-rule-home-'));
  project = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-name-rule-proj-'));
  saved = { HOME: process.env.HOME, USER: process.env.USER };
  process.env.HOME = home;
  delete process.env.USER;
  write(path.join(home, '.secretless-ai', 'config.json'), JSON.stringify({ backend: 'local' }, null, 2));
});

afterEach(() => {
  for (const [name, value] of Object.entries(saved)) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
  for (const dir of [home, project]) fs.rmSync(dir, { recursive: true, force: true });
});

function write(fullPath: string, text: string): string {
  fs.mkdirSync(path.dirname(fullPath), { recursive: true });
  fs.writeFileSync(fullPath, text);
  return fullPath;
}

const vaultDir = () => path.join(home, '.secretless-ai', 'mcp-vault');
/** The store the wrapper builds from args with no --backend, --vault-dir or --vault-key. */
const store = () => new McpVault({ storeDir: vaultDir(), backendType: 'local' });
/** The same store with no name rule in front of it, as an earlier version wrote into it. */
const rawStore = () => createBackend('local', { storeDir: vaultDir() });
const cursorConfig = () => path.join(home, '.cursor', 'mcp.json');
const protect = () => protectMcp({ projectDir: project, wrapperPath: WRAPPER_PATH });

/** A server with a secret in its env, not yet protected. */
const plain = () => ({ command: process.execPath, args: ['-e', 'x'], env: { [NAME]: VALUE } });
/** A server that runs through this build's wrapper with these wrapper args and no --binding. */
const wrapped = (own: string[], env: Record<string, string> = {}) => ({
  command: WRAPPER_PATH,
  args: [...own, '--', process.execPath, '-e', 'x'],
  env,
});
const configText = (servers: Record<string, unknown>) => JSON.stringify({ mcpServers: servers }, null, 2);

/** A store held in memory. */
class MemoryStore implements WritableSecretBackend {
  readonly name = 'local';
  readonly entries = new Map<string, string>();

  async resolve(at: string, options?: ResolveOptions): Promise<Record<string, string>> {
    const found: Record<string, string> = {};
    for (const [key, value] of this.entries) {
      if (key === at || (!options?.exact && key.startsWith(`${at}/`))) found[key] = value;
    }
    return found;
  }

  async healthCheck() {
    return { healthy: true, latencyMs: 0 };
  }

  async store(key: string, value: string): Promise<void> {
    this.entries.set(key, value);
  }

  async delete(key: string): Promise<boolean> {
    return this.entries.delete(key);
  }
}

function bindingFor(client: string, server: string): McpBinding {
  return {
    schema: 1,
    id: newBindingId(),
    scope: 'home',
    file: path.join(os.tmpdir(), 'secretless-name-rule', 'mcp.json'),
    client,
    server,
    commandDigest: commandDigest(process.execPath, ['-e', 'x']),
    boundAt: new Date().toISOString(),
    boundBy: 'test',
    boundOn: newBindingId(),
  };
}

describe('the store\'s write rule (mcpNameProblem)', () => {
  it('gives, in order, the empty name, a character outside the class, then a first character -, and takes every other name', () => {
    expect(mcpNameProblem('')).toBe('it is empty');
    expect(mcpNameProblem('-my.server')).toBe(CLASS);
    expect(mcpNameProblem('my server')).toBe(CLASS);
    expect(mcpNameProblem('-')).toBe(LEADING_DASH);
    expect(mcpNameProblem('--server')).toBe(LEADING_DASH);
    expect(mcpNameProblem('-srv')).toBe(LEADING_DASH);
    for (const name of ['github', 'my-server', 'server-', '_srv', 'a-', 'A_1-b']) {
      expect(mcpNameProblem(name)).toBeUndefined();
    }
  });

  it('storeServerSecrets and storeBinding refuse a client or a server name that begins with -, and store nothing', async () => {
    const memory = new MemoryStore();
    const vault = new McpVault({ backend: memory });
    for (const [client, server] of [['cursor', '-srv'], ['-x', 'github']]) {
      await expect(vault.storeServerSecrets(client, server, { [NAME]: VALUE })).rejects.toThrow(LEADING_DASH);
      await expect(vault.storeBinding(client, server, bindingFor(client, server))).rejects.toThrow(LEADING_DASH);
    }
    expect([...memory.entries.keys()]).toEqual([]);
  });
});

describe('n1: protect-mcp leaves a server whose name begins with - as it is', () => {
  it('n1: the server is left with the refused-name reason, no key under its pair exists afterwards, and its entry is byte-identical', async () => {
    const before = configText({ '-srv': plain() });
    const file = write(cursorConfig(), before);

    const result = await protect();

    expect(result.refusedName.map((s) => [s.client, s.server, s.reason])).toEqual([
      ['cursor', '-srv', `the store refuses its name, since ${LEADING_DASH}`],
    ]);
    expect(result.servers).toEqual([]);
    expect(result.secretsFound).toBe(0);
    expect(await rawStore().resolve('mcp/cursor/-srv')).toEqual({});
    expect(await store().getBinding('cursor', '-srv')).toBeUndefined();
    expect(fs.readFileSync(file, 'utf-8')).toBe(before);
  });

  it('n1: with a server beside it, that server is protected and the refused entry keeps every byte of its own JSON', async () => {
    const refused = plain();
    const file = write(cursorConfig(), configText({ '-srv': refused, github: plain() }));

    const result = await protect();

    expect(result.refusedName.map((s) => s.server)).toEqual(['-srv']);
    expect(result.servers.map((s) => `${s.client}/${s.server}`)).toEqual(['cursor/github']);
    const servers = JSON.parse(fs.readFileSync(file, 'utf-8')).mcpServers;
    expect(JSON.stringify(servers['-srv'])).toBe(JSON.stringify(refused));
    expect(servers.github.env).toEqual({});
    expect(await rawStore().resolve('mcp/cursor/-srv')).toEqual({});
  });
});

describe('the config rewrite applies the store\'s write rule', () => {
  it('rewriteConfig leaves a server whose name begins with - as it is, and wraps the server beside it', () => {
    const refused = plain();
    const file = write(cursorConfig(), configText({ '-srv': refused, github: plain() }));

    rewriteConfig(file, 'cursor', { '-srv': { [NAME]: VALUE }, github: { [NAME]: VALUE } }, WRAPPER_PATH, path.join(home, 'backups'));

    const servers = JSON.parse(fs.readFileSync(file, 'utf-8')).mcpServers;
    expect(JSON.stringify(servers['-srv'])).toBe(JSON.stringify(refused));
    expect(servers.github.command).toBe(WRAPPER_PATH);
    expect(servers.github.args.slice(0, 4)).toEqual(['--server', 'github', '--client', 'cursor']);
  });
});

describe('n2: a pair an earlier version stored under a name that begins with - stays readable and removable, and gets no binding', () => {
  it('n2: getServerSecrets returns its names, removeServerSecrets deletes them, and storeBinding for the pair throws', async () => {
    const memory = new MemoryStore();
    memory.entries.set(`mcp/cursor/-srv/${NAME}`, VALUE);
    const vault = new McpVault({ backend: memory });

    expect(await vault.getServerSecrets('cursor', '-srv')).toEqual({ [NAME]: VALUE });
    await expect(vault.storeBinding('cursor', '-srv', bindingFor('cursor', '-srv'))).rejects.toThrow(LEADING_DASH);
    expect(await vault.getBinding('cursor', '-srv')).toBeUndefined();
    expect([...memory.entries.keys()]).toEqual([`mcp/cursor/-srv/${NAME}`]);

    await vault.removeServerSecrets('cursor', '-srv');

    expect(await vault.getServerSecrets('cursor', '-srv')).toEqual({});
    expect([...memory.entries.keys()]).toEqual([]);
  });

  it('n2: protect-mcp leaves the entry whose wrapper reads that pair with the refused-name reason, and writes nothing', async () => {
    await rawStore().store(`mcp/cursor/-srv/${NAME}`, VALUE);
    const before = configText({ legacy: wrapped(['--server', '-srv', '--client', 'cursor']) });
    const file = write(cursorConfig(), before);

    const result = await protect();

    expect(result.unbound.map((s) => [s.client, s.server, s.reason])).toEqual([
      ['cursor', 'legacy', `its wrapper reads its secrets by the server name "-srv", which the store refuses, since ${LEADING_DASH}`],
    ]);
    expect(await store().getBinding('cursor', '-srv')).toBeUndefined();
    expect(await rawStore().resolve('mcp/cursor/-srv')).toEqual({ [`mcp/cursor/-srv/${NAME}`]: VALUE });
    expect(fs.readFileSync(file, 'utf-8')).toBe(before);
  });
});

describe('n3: a wrapped entry in the project\'s .mcp.json whose --client begins with -', () => {
  it('n3: no record is written, and the entry is left with the reason', async () => {
    const before = configText({ github: wrapped(['--server', 'github', '--client', '-x'], { [NAME]: VALUE }) });
    const file = write(path.join(project, '.mcp.json'), before);

    const result = await protect();

    const reason = `its wrapper reads its secrets by the client name "-x", which the store refuses, since ${LEADING_DASH}`;
    expect(result.unbound.map((s) => [s.server, s.reason])).toEqual([['github', reason]]);
    expect(result.unmoved.map((s) => [s.server, s.reason])).toEqual([['github', reason]]);
    expect(result.secretsFound).toBe(0);
    expect(await store().getBinding('-x', 'github')).toBeUndefined();
    expect(await rawStore().resolve('mcp/-x/github')).toEqual({});
    expect(fs.readFileSync(file, 'utf-8')).toBe(before);
  });
});
