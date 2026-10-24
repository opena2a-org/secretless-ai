import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { protectMcp } from './protect';
import { McpVault, commandDigest, newBindingId } from './vault';
import { rewriteConfig } from './rewrite';
import { createBackend } from '../backends/factory';
import type { ResolveOptions, WritableSecretBackend } from '../backends/types';
import { runMcpUnprotect, runProtectMcp } from '../commands/mcp';

/**
 * A binding on a store shared between machines (1password, vault, gcp-sm):
 * its pair and its binding may be read by entries on other machines, so a
 * file or a binding absent on this machine proves nothing about them.
 *
 * Every command runs in this process, as the CLI runs it, with HOME set to a
 * scratch directory and `1password` configured. Where a case builds that
 * backend it gets the store double below, which keeps what it is given in
 * memory and starts nothing; every other call reaches the real function.
 * Values are assembled at run time and are not credentials.
 */

vi.mock('../backends/factory', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../backends/factory')>();
  return { ...actual, createBackend: vi.fn(actual.createBackend) };
});

/** A shared store held in memory, named as the 1password backend is. */
class SharedStore implements WritableSecretBackend {
  readonly name = '1password';
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

const WRAPPER_PATH = '/usr/local/bin/secretless-mcp';
const NAME = ['MY', 'SERVICE', 'API', 'KEY'].join('_');
const VALUE = ['stand', 'in', 'value', String(process.pid)].join('-');

let home: string;
let project: string;
let shared: SharedStore;
let saved: Record<'HOME' | 'USER', string | undefined>;

beforeEach(async () => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-shared-home-'));
  project = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-shared-proj-'));
  saved = { HOME: process.env.HOME, USER: process.env.USER };
  process.env.HOME = home;
  delete process.env.USER;
  write(path.join(home, '.secretless-ai', 'config.json'), { backend: '1password' });
  shared = new SharedStore();
  const actual = await vi.importActual<typeof import('../backends/factory')>('../backends/factory');
  vi.mocked(createBackend).mockImplementation((type, config, strict, options) =>
    type === '1password' ? shared : actual.createBackend(type, config, strict, options));
});

afterEach(() => {
  vi.mocked(createBackend).mockReset();
  for (const [name, value] of Object.entries(saved)) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
  for (const d of [home, project]) fs.rmSync(d, { recursive: true, force: true });
});

function write(fullPath: string, content: unknown): string {
  fs.mkdirSync(path.dirname(fullPath), { recursive: true });
  fs.writeFileSync(fullPath, JSON.stringify(content, null, 2));
  return fullPath;
}

const sharedVault = () => new McpVault({ backend: shared });
const backupDir = () => path.join(home, '.secretless-ai', 'mcp-backups');
const plain = () => ({ command: process.execPath, args: ['-e', 'x'], env: { [NAME]: VALUE } });

/** A command of the CLI in this process, from `cwd`, with what it prints. */
async function run(command: () => Promise<number>, cwd = project): Promise<{ code: number; output: string }> {
  const lines: string[] = [];
  const capture = (...parts: unknown[]) => { lines.push(parts.map(String).join(' ')); };
  const log = vi.spyOn(console, 'log').mockImplementation(capture);
  const error = vi.spyOn(console, 'error').mockImplementation(capture);
  const dir = vi.spyOn(process, 'cwd').mockReturnValue(cwd);
  try {
    const code = await command();
    return { code, output: lines.join('\n') };
  } finally {
    log.mockRestore();
    error.mockRestore();
    dir.mockRestore();
  }
}

describe('mcp-unprotect on a shared store', () => {
  it('u3: a pair with no binding is left, though the restored file holds its values', async () => {
    // As an earlier version left it: the entry wrapped with no --binding,
    // protect-mcp's backup of the file holding the values, the values stored.
    const file = write(path.join(project, '.mcp.json'), { mcpServers: { github: plain() } });
    rewriteConfig(file, 'claude-code', { github: { [NAME]: VALUE } }, WRAPPER_PATH, backupDir());
    await sharedVault().storeServerSecrets('claude-code', 'github', { [NAME]: VALUE });

    const { code, output } = await run(() => runMcpUnprotect());

    expect(code).toBe(0);
    expect(JSON.parse(fs.readFileSync(file, 'utf-8')).mcpServers.github).toEqual(plain());
    expect(output).toContain(
      '  ? claude-code/github: left in the store; it has no binding, and an entry on another machine may read it from the 1password backend.',
    );
    expect(output).not.toContain('Deleted from the store');
    expect(await sharedVault().getServerSecrets('claude-code', 'github')).toEqual({ [NAME]: VALUE });
  });
});

describe('protect-mcp on a shared store', () => {
  /** A server that runs through the wrapper, as an earlier version wrote it: no --binding. */
  const wrappedUnbound = (client: string, server: string) => ({
    command: WRAPPER_PATH,
    args: ['--server', server, '--client', client, '--', process.execPath, '-e', 'x'],
    env: {},
  });

  it('e3: a home binding whose file is absent here is not taken over, and the line says only that the file was not found on this machine', async () => {
    const gone = path.join(home, '.cursor', 'mcp.json');
    await sharedVault().storeBinding('cursor', 'github', {
      schema: 1,
      id: newBindingId(),
      scope: 'home',
      file: gone,
      client: 'cursor',
      server: 'github',
      commandDigest: commandDigest(process.execPath, ['-e', 'x']),
      boundAt: new Date().toISOString(),
      boundBy: 'test',
    });
    await sharedVault().storeServerSecrets('cursor', 'github', { [NAME]: VALUE });
    const settings = write(path.join(home, '.claude', 'settings.json'), { mcpServers: { github: wrappedUnbound('cursor', 'github') } });
    const before = fs.readFileSync(settings, 'utf-8');
    const record = await sharedVault().getBinding('cursor', 'github');

    const { code, output } = await run(() => runProtectMcp([]));

    expect(code).toBe(0);
    expect(output).toContain(
      `    ? github: not bound: the secrets stored under cursor/github are bound to server "github" in ${gone}. `
        + `To run this server as well, add it again under a new name with its values and run \`npx secretless-ai protect-mcp\`. ${gone} was not found on this machine.`,
    );
    expect(output).not.toContain('no longer exists');
    expect(output).not.toContain('mcp-forget');
    expect(output).not.toContain('took over');
    expect(fs.readFileSync(settings, 'utf-8')).toBe(before);
    expect(await sharedVault().getBinding('cursor', 'github')).toEqual(record);
  });

  it('e3: a .mcp.json entry whose project directory moved is not bound again, though this machine\'s backup holds the stored values', async () => {
    const a = fs.realpathSync(project);
    const file = write(path.join(a, '.mcp.json'), { mcpServers: { github: plain() } });
    await protectMcp({ projectDir: a, wrapperPath: WRAPPER_PATH });
    const record = await sharedVault().getBinding('claude-code', 'github');
    expect(record).toMatchObject({ scope: 'project', file });
    const a2 = `${a}-moved`;
    fs.renameSync(a, a2);
    const moved = path.join(a2, '.mcp.json');
    const before = fs.readFileSync(moved, 'utf-8');

    try {
      const { output } = await run(() => runProtectMcp([]), a2);

      expect(output).toContain(`it carries the binding of server "github" in ${file}, so the wrapper gives it that server's secrets. ${file} was not found on this machine.`);
      expect(output).not.toContain('bound again');
      expect(output).not.toContain('mcp-forget');
      expect(fs.readFileSync(moved, 'utf-8')).toBe(before);
      expect(await sharedVault().getBinding('claude-code', 'github')).toEqual(record);
    } finally {
      fs.renameSync(a2, a);
    }
  });
});
