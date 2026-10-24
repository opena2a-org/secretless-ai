import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { protectMcp } from './protect';
import { McpVault, commandDigest } from './vault';
import { rewriteConfig } from './rewrite';
import { runMcpUnprotect, runProtectMcp } from '../commands/mcp';

/**
 * protect-mcp binds each pair it stores to the config entry its secrets came
 * from, and the command that entry starts: a record beside the pair, and its
 * id in the entry's wrapper args. It binds the entries an earlier version
 * protected only where the secrets are shown to be theirs, binds a home entry
 * again after its command changes, and lists what it bound and what it could
 * not bind, with why. mcp-unprotect clears a pair only where the restored file
 * holds its values.
 *
 * Every command runs in this process, as the CLI runs it: no home directory
 * given, HOME set to a scratch directory and the local backend configured,
 * so its store is the encrypted file under ~/.secretless-ai/mcp-vault. Values
 * are assembled at run time and are not credentials.
 */

// The wrapper protect-mcp writes into a config: this build's, as the built
// CLI writes it, so its runs read these entries as on its own wrapper (an
// entry on another build's wrapper is re-pointed: binding-repoint.test.ts).
const WRAPPER_PATH = path.resolve(__dirname, '..', '..', 'dist', 'mcp-wrapper.js');
const NAME = ['MY', 'SERVICE', 'API', 'KEY'].join('_');
const VALUE = ['stand', 'in', 'value', String(process.pid)].join('-');
const ID = /^[0-9a-f]{32}$/;

let home: string;
let project: string;
let saved: Record<'HOME' | 'USER', string | undefined>;

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-bind-home-'));
  project = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-bind-proj-'));
  saved = { HOME: process.env.HOME, USER: process.env.USER };
  process.env.HOME = home;
  delete process.env.USER;
  write(path.join(home, '.secretless-ai', 'config.json'), { backend: 'local' });
});

afterEach(() => {
  for (const [name, value] of Object.entries(saved)) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
  for (const dir of [home, project]) fs.rmSync(dir, { recursive: true, force: true });
});

function write(fullPath: string, content: unknown): string {
  fs.mkdirSync(path.dirname(fullPath), { recursive: true });
  fs.writeFileSync(fullPath, JSON.stringify(content, null, 2));
  return fullPath;
}

/** The store the wrapper builds from args with no --backend, --vault-dir or --vault-key. */
const store = () => new McpVault({ storeDir: path.join(home, '.secretless-ai', 'mcp-vault'), backendType: 'local' });
const backupDir = () => path.join(home, '.secretless-ai', 'mcp-backups');
const cursorConfig = () => path.join(home, '.cursor', 'mcp.json');
const projectConfig = (dir = project) => path.join(dir, '.mcp.json');

/** A server with a secret in its env, not yet protected. */
const plain = (args: string[] = ['-e', 'x']) => ({ command: process.execPath, args, env: { [NAME]: VALUE } });
/** A server that runs through the wrapper, as an earlier version wrote it: no --binding. */
const wrappedUnbound = (client: string, server: string, child: string[] = [process.execPath, '-e', 'x']) => ({
  command: WRAPPER_PATH,
  args: ['--server', server, '--client', client, '--', ...child],
  env: {},
});

const servers = (file: string) => JSON.parse(fs.readFileSync(file, 'utf-8')).mcpServers;

/** The args before the wrapper's own `--`, the id they carry, and the command after it. */
function split(args: string[]): { own: string[]; id: string | undefined; child: string[] } {
  const at = args.indexOf('--');
  const own = args.slice(0, at);
  const b = own.indexOf('--binding');
  return { own, id: b === -1 ? undefined : own[b + 1], child: args.slice(at + 1) };
}

const protect = (projectDir = project) => protectMcp({ projectDir, wrapperPath: WRAPPER_PATH });

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

describe('protect-mcp binds each pair it stores to the entry the secrets came from', () => {
  it('p1: a fresh protection stores the binding and writes its id before the wrapper\'s --', async () => {
    const file = write(cursorConfig(), { mcpServers: { github: plain() } });

    await protect();

    const entry = servers(file).github;
    const { own, id, child } = split(entry.args);
    expect(own).toEqual(['--server', 'github', '--client', 'cursor', '--binding', expect.stringMatching(ID)]);
    expect(child).toEqual([process.execPath, '-e', 'x']);
    expect(await store().getBinding('cursor', 'github')).toEqual({
      schema: 1,
      id,
      scope: 'home',
      file,
      client: 'cursor',
      server: 'github',
      commandDigest: commandDigest(process.execPath, ['-e', 'x']),
      boundAt: expect.any(String),
      boundBy: expect.any(String),
    });
    expect(await store().getServerSecrets('cursor', 'github')).toEqual({ [NAME]: VALUE });
  });

  it('p2: a home entry an earlier version wrapped, with no --binding and no binding, is bound, its command unchanged', async () => {
    const before = wrappedUnbound('cursor', 'github');
    const file = write(cursorConfig(), { mcpServers: { github: before } });
    await store().storeServerSecrets('cursor', 'github', { [NAME]: VALUE });

    const { code, output } = await run(() => runProtectMcp([]));

    expect(code).toBe(0);
    const entry = servers(file).github;
    const { own, id, child } = split(entry.args);
    expect(entry.command).toBe(WRAPPER_PATH);
    expect(own).toEqual([...split(before.args).own, '--binding', id]);
    expect(child).toEqual(split(before.args).child);
    expect((await store().getBinding('cursor', 'github'))?.id).toBe(id);
    expect(output).toContain(`  cursor (${file})\n    + github: bound\n\n  1 server(s) bound to their config entries.\n`);
    expect(output).not.toContain(id);
  });

  it('p3: a .mcp.json entry is bound when the first backup of the file holds the stored values, and left when there is no backup', async () => {
    // As an earlier version left it: the backup of the file as it was, the
    // entry wrapped with no --binding, the values stored.
    const file = write(projectConfig(), { mcpServers: { github: plain() } });
    rewriteConfig(file, 'claude-code', { github: { [NAME]: VALUE } }, WRAPPER_PATH, backupDir());
    await store().storeServerSecrets('claude-code', 'github', { [NAME]: VALUE });

    const bound = await protect();

    expect(bound.bound).toEqual([{ client: 'claude-code', filePath: file, projectPath: '.mcp.json', server: 'github' }]);
    expect(await store().getBinding('claude-code', 'github')).toMatchObject({ scope: 'project', file, id: split(servers(file).github.args).id });

    // The same entry and values with no backup of the file.
    await store().removeServerSecrets('claude-code', 'github');
    fs.rmSync(backupDir(), { recursive: true, force: true });
    write(file, { mcpServers: { github: wrappedUnbound('claude-code', 'github') } });
    await store().storeServerSecrets('claude-code', 'github', { [NAME]: VALUE });

    const left = await protect();

    expect(left.unbound).toEqual([{
      client: 'claude-code',
      filePath: file,
      projectPath: '.mcp.json',
      server: 'github',
      reason: "the secrets stored under claude-code/github are not in protect-mcp's backup of this file, and a project-level entry is bound only to values protect-mcp stores from its file. "
        + "If this entry is yours, put the server's values in its env, and run `npx secretless-ai protect-mcp`.",
    }]);
    expect(await store().getBinding('claude-code', 'github')).toBeUndefined();
    expect(split(servers(file).github.args).id).toBeUndefined();
  });

  it('p4: two rewritten configs that read one pair are both left, each naming the other', async () => {
    const cursor = write(cursorConfig(), { mcpServers: { github: wrappedUnbound('cursor', 'github') } });
    const settings = write(path.join(home, '.claude', 'settings.json'), { mcpServers: { github: wrappedUnbound('cursor', 'github') } });
    await store().storeServerSecrets('cursor', 'github', { [NAME]: VALUE });

    const { output } = await run(() => runProtectMcp([]));

    const reason = (other: string) =>
      `not bound: cursor/github is also read by server "github" in ${other}, and the secrets stored under a name are bound to one entry only. `
      + 'Keep one of these entries, remove the others, and run `npx secretless-ai protect-mcp`; to run another as well, add it again under a new name with its values.';
    expect(output).toContain(`  cursor (${cursor})\n    ? github: ${reason(settings)}\n`);
    expect(output).toContain(`  claude-code (${settings})\n    ? github: ${reason(cursor)}\n`);
    expect(output).toContain('  2 server(s) run through the wrapper but are not bound, so the wrapper does not start them. Each line above says what to change.\n');
    expect(output).not.toContain('Protected servers start as before.');
    expect(await store().getBinding('cursor', 'github')).toBeUndefined();
  });

  it('p5: a bound home entry whose command changed is bound again; a .mcp.json one is left and its binding kept', async () => {
    const file = write(cursorConfig(), { mcpServers: { github: plain() } });
    await protect();
    const id = split(servers(file).github.args).id;
    const config = JSON.parse(fs.readFileSync(file, 'utf-8'));
    config.mcpServers.github.args = [...config.mcpServers.github.args, 'extra'];
    write(file, config);

    const { output } = await run(() => runProtectMcp([]));

    expect(await store().getBinding('cursor', 'github')).toMatchObject({
      id,
      commandDigest: commandDigest(process.execPath, ['-e', 'x', 'extra']),
    });
    expect(output).toContain(`  cursor (${file})\n    ~ github: its command or arguments changed since it was bound; bound again\n\n  1 server(s) bound to their config entries.\n`);

    const mcp = write(projectConfig(), { mcpServers: { db: plain() } });
    await protect();
    const record = await store().getBinding('claude-code', 'db');
    const changed = JSON.parse(fs.readFileSync(mcp, 'utf-8'));
    changed.mcpServers.db.args = [...changed.mcpServers.db.args, 'extra'];
    write(mcp, changed);

    const left = await run(() => runProtectMcp([]));

    expect(await store().getBinding('claude-code', 'db')).toEqual(record);
    expect(left.output).toContain(
      `    ? db: not bound: its command or arguments changed since it was bound, and a project-level entry is bound again only when protect-mcp stores its values. `
        + "If you made the change, put the server's values in its env, and run `npx secretless-ai protect-mcp`.\n",
    );
  });

  it('p6: a .mcp.json entry that carries a home binding is listed as a copy, the binding is replaced, and the copy is not written', async () => {
    const file = write(cursorConfig(), { mcpServers: { github: plain() } });
    await protect();
    const home0 = fs.readFileSync(file, 'utf-8');
    const record = await store().getBinding('cursor', 'github');
    const copy = write(projectConfig(), { mcpServers: { github: servers(file).github } });
    const copy0 = fs.readFileSync(copy, 'utf-8');

    const { output } = await run(() => runProtectMcp([]));

    expect(output).toContain(
      `    ? github: a copy of a bound entry: it carried the binding of server "github" in ${file}; the binding was replaced, and this entry no longer starts. `
        + 'Remove this entry; to run the server here as well, add it again under a new name with its values and run `npx secretless-ai protect-mcp`.\n\n'
        + '  1 copied binding(s) replaced; those copies no longer start.\n',
    );
    expect(output).not.toContain('Protected servers start as before.');
    expect(fs.readFileSync(copy, 'utf-8')).toBe(copy0);
    const after = await store().getBinding('cursor', 'github');
    expect(ID.test(after?.id ?? '') && after?.id !== record!.id, 'the binding holds a new id').toBe(true);
    expect({ ...after, id: '', boundAt: '', boundBy: '' }).toEqual({ ...record, id: '', boundAt: '', boundBy: '' });
    expect(home0.split(record!.id).join(after!.id) === fs.readFileSync(file, 'utf-8'), 'the home entry changed only in its id').toBe(true);
    expect(output.includes(record!.id) || output.includes(after!.id), 'an id is printed').toBe(false);
  });

  it('p6b: a home entry that carries a project binding is listed as a copy, and nothing is written: a project binding is not replaced', async () => {
    const bound = write(projectConfig(), { mcpServers: { github: plain() } });
    await protect();
    const record = await store().getBinding('claude-code', 'github');
    expect(record?.scope).toBe('project');
    const bound0 = fs.readFileSync(bound, 'utf-8');
    const copy = write(cursorConfig(), { mcpServers: { github: servers(bound).github } });
    const copy0 = fs.readFileSync(copy, 'utf-8');

    const { output } = await run(() => runProtectMcp([]));

    expect(output).toContain(
      `    ? github: a copy of a bound entry: it carries the binding of server "github" in ${bound}, so the wrapper gives it that server's secrets. `
        + 'Remove this entry; to run the server here as well, add it again under a new name with its values and run `npx secretless-ai protect-mcp`.\n\n'
        + '  1 server(s) are copies of a bound entry and receive its secrets.\n',
    );
    expect(fs.readFileSync(copy, 'utf-8')).toBe(copy0);
    expect(fs.readFileSync(bound, 'utf-8')).toBe(bound0);
    expect(JSON.stringify(await store().getBinding('claude-code', 'github')) === JSON.stringify(record), 'the binding is unchanged').toBe(true);
    expect(output.includes(record!.id), 'an id is printed').toBe(false);
  });

  it('p7: an unprotected server whose pair is bound to an entry in another project is left as it is', async () => {
    const other = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-bind-other-'));
    try {
      const bound = write(projectConfig(other), { mcpServers: { github: plain() } });
      await protect(other);
      const record = await store().getBinding('claude-code', 'github');
      expect(record).toMatchObject({ scope: 'project', file: bound });
      const claudeJson = write(path.join(home, '.claude.json'), { mcpServers: { github: plain() } });
      const before = fs.readFileSync(claudeJson, 'utf-8');

      const result = await protect();

      expect(result.sharedName).toEqual([{
        client: 'claude-code',
        filePath: claudeJson,
        server: 'github',
        protectedIn: { filePath: bound },
        boundTo: { server: 'github', file: bound },
      }]);
      expect(result.servers).toEqual([]);
      expect(fs.readFileSync(claudeJson, 'utf-8')).toBe(before);
      expect(await store().getBinding('claude-code', 'github')).toEqual(record);
    } finally {
      fs.rmSync(other, { recursive: true, force: true });
    }
  });

  it('p8: a renamed entry takes over the binding of the entry no longer in its file; a .mcp.json entry does not take over a home one', async () => {
    const file = write(cursorConfig(), { mcpServers: { github: plain() } });
    await protect();
    const old = await store().getBinding('cursor', 'github');
    // Renamed in its file: its args still read cursor/github and carry the id.
    write(file, { mcpServers: { gh: servers(file).github } });

    const { output } = await run(() => runProtectMcp([]));

    const taken = await store().getBinding('cursor', 'github');
    expect(taken).toMatchObject({ server: 'gh', file, scope: 'home' });
    expect(taken!.id).not.toBe(old!.id);
    expect(split(servers(file).gh.args).id).toBe(taken!.id);
    expect(output).toContain(`  cursor (${file})\n    + gh: bound (took over the binding of server "github", no longer in ${file})\n`);
    expect(output).not.toContain(old!.id);
    expect(output).not.toContain(taken!.id);

    // The home entry removed, a .mcp.json entry reading the same pair is not given it.
    write(file, { mcpServers: {} });
    const mcp = write(projectConfig(), { mcpServers: { github: wrappedUnbound('cursor', 'github') } });
    const mcp0 = fs.readFileSync(mcp, 'utf-8');

    const result = await protect();

    expect(result.bound).toEqual([]);
    expect(result.unbound.map((s) => s.server)).toEqual(['github']);
    expect(await store().getBinding('cursor', 'github')).toEqual(taken);
    expect(fs.readFileSync(mcp, 'utf-8')).toBe(mcp0);
  });
});

describe('the store keeps a binding beside its pair', () => {
  it('p9: removeServerSecrets deletes the binding, and listEntries lists pairs as it did', async () => {
    const file = write(cursorConfig(), { mcpServers: { github: plain() } });
    await protect();
    expect(await store().getBinding('cursor', 'github')).toMatchObject({ file });

    expect(await store().listEntries()).toEqual([{ client: 'cursor', server: 'github', keyCount: 1 }]);

    await store().removeServerSecrets('cursor', 'github');

    expect(await store().getBinding('cursor', 'github')).toBeUndefined();
    expect(await store().getServerSecrets('cursor', 'github')).toEqual({});
    expect(await store().listEntries()).toEqual([]);
  });
});

describe('mcp-unprotect clears a pair only where the restored file holds its values', () => {
  it('p10: deletes the pair and its binding when the restored entry holds every stored value, and leaves it otherwise', async () => {
    const file = write(cursorConfig(), { mcpServers: { github: plain() } });
    const original = fs.readFileSync(file, 'utf-8');
    await protect();

    const cleared = await run(() => runMcpUnprotect());

    expect(cleared.output).toContain(`  + Restored: ${file}\n  - Deleted from the store: cursor/github (1 name(s); the restored file holds the same values)\n`);
    expect(fs.readFileSync(file, 'utf-8')).toBe(original);
    expect(await store().getBinding('cursor', 'github')).toBeUndefined();
    expect(await store().getServerSecrets('cursor', 'github')).toEqual({});

    // Protected again, then the stored value replaced: the restored file does not hold it.
    await protect();
    const replaced = ['other', 'stand', 'in', String(process.pid)].join('-');
    await store().storeServerSecrets('cursor', 'github', { [NAME]: replaced });
    const record = await store().getBinding('cursor', 'github');

    const left = await run(() => runMcpUnprotect());

    expect(left.output).toContain(`  ? cursor/github: left in the store: ${NAME}. The restored file does not hold these values.\n`);
    expect(left.output).not.toContain(replaced);
    expect(left.output).not.toContain(VALUE);
    expect(await store().getServerSecrets('cursor', 'github')).toEqual({ [NAME]: replaced });
    expect(await store().getBinding('cursor', 'github')).toEqual(record);
  });
});
