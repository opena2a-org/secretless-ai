import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { execFileSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { FIRST_BINDING_VERSION, protectMcp } from './protect';
import { McpVault } from './vault';
import { createBackend } from '../backends/factory';

/**
 * The pair an entry on a wrapper that does not check its binding reads (P):
 * what protect-mcp does with an entry added to read P, and the end of the
 * line mcp-status prints for such an entry.
 *
 * While the entry is in its file, an added entry that reads P is left as
 * sharing the name, whatever config either is in. Once it is removed, P
 * still holds its names: an added entry in the project's .mcp.json is left,
 * one in a home config is bound only when each value equals the stored one,
 * and one under a new name is bound with P left as it was. The line for an
 * entry on such a wrapper always ends with what protect-mcp does about it.
 *
 * protect-mcp runs in this process with no home directory given, HOME set to
 * a scratch directory and the local backend configured; mcp-status runs from
 * the build (`dist/`). Values are assembled at run time and are not
 * credentials.
 */

const CLI_PATH = path.resolve(__dirname, '..', '..', 'dist', 'cli.js');
const WRAPPER_JS = path.resolve(__dirname, '..', '..', 'dist', 'mcp-wrapper.js');
const THIS_VERSION: string = JSON.parse(fs.readFileSync(path.resolve(__dirname, '..', '..', 'package.json'), 'utf-8')).version;
const NAME = ['MY', 'SERVICE', 'API', 'KEY'].join('_');
const VALUE = ['stand', 'in', 'value', String(process.pid)].join('-');
const OTHER = ['other', 'stand', 'in', 'value', String(process.pid)].join('-');

const OLD_LINE = 'protected, but it runs through a wrapper that does not check its binding';
const UNREAD_LINE = 'protected, but it runs through a wrapper whose version could not be read';
const REPOINTS = /^; `[^`]+` re-points it to this version's wrapper$/;
const NOT_REWRITTEN = '; protect-mcp does not rewrite this config, so it does not re-point it';
const OWN_VERSION_UNREAD = "; this build's own version could not be read, so protect-mcp does not re-point it";

let home: string;
let project: string;
let scratch: string;
let saved: Record<'HOME' | 'USER', string | undefined>;

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-old-wrapper-home-'));
  project = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-old-wrapper-proj-'));
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-old-wrapper-scratch-'));
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
  for (const dir of [home, project, scratch]) fs.rmSync(dir, { recursive: true, force: true });
});

function write(fullPath: string, content: unknown): string {
  fs.mkdirSync(path.dirname(fullPath), { recursive: true });
  fs.writeFileSync(fullPath, JSON.stringify(content, null, 2));
  return fullPath;
}

const vaultDir = () => path.join(home, '.secretless-ai', 'mcp-vault');
/** The store the wrapper builds from args with no --backend, --vault-dir or --vault-key. */
const store = () => new McpVault({ storeDir: vaultDir(), backendType: 'local' });
/** Every key stored under a pair, with its value, read from the same store. */
const keysUnder = (client: string, server: string) => createBackend('local', { storeDir: vaultDir() }).resolve(`mcp/${client}/${server}`);
const homeCursor = () => path.join(home, '.cursor', 'mcp.json');
const homeClaude = () => path.join(home, '.claude', 'settings.json');
const projectMcpJson = () => path.join(project, '.mcp.json');
const projectCursor = () => path.join(project, '.cursor', 'mcp.json');
const servers = (file: string) => JSON.parse(fs.readFileSync(file, 'utf-8')).mcpServers;
const protect = () => protectMcp({ projectDir: project, wrapperPath: WRAPPER_JS });

/** A scratch wrapper file that reads `version` as an installed copy does (wrapper-version.json beside it). */
function scratchWrapper(label: string, version: string): string {
  const file = path.join(scratch, label, 'mcp-wrapper.js');
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, '// a scratch wrapper: never started\n');
  fs.writeFileSync(path.join(path.dirname(file), 'wrapper-version.json'), JSON.stringify({ version }));
  return file;
}

/** An entry on `wrapper` that reads the pair client/server. */
const onWrapper = (wrapper: string, client: string, server: string) => ({
  command: wrapper,
  args: ['--server', server, '--client', client, '--', process.execPath, '-e', '0'],
});
/** An entry on a wrapper that reads a version below FIRST_BINDING_VERSION, reading client/server. */
const oldEntry = (client: string, server: string) => onWrapper(scratchWrapper('old', '0.0.1'), client, server);
/** A server with a secret in its env, not yet protected. */
const plain = (value = VALUE) => ({ command: process.execPath, args: ['-e', 'x'], env: { [NAME]: value } });

describe('p1: while the old-wrapper entry is in its file, an added entry that reads its pair is left as sharing the name', () => {
  const placements: Array<{ label: string; old: () => string; client: string; added: () => string }> = [
    { label: 'both in one home config', old: homeCursor, client: 'cursor', added: homeCursor },
    { label: 'the old entry in a project-level config protect-mcp leaves as it is', old: projectCursor, client: 'cursor', added: homeCursor },
    { label: 'the added entry in the project\'s .mcp.json', old: homeClaude, client: 'claude-code', added: projectMcpJson },
  ];
  for (const { label, old, client, added } of placements) {
    it(`p1: ${label}`, async () => {
      await store().storeServerSecrets(client, 'github', { [NAME]: VALUE });
      const before = await keysUnder(client, 'github');
      const oldServers = { legacy: oldEntry(client, 'github') };
      if (old() === added()) {
        write(added(), { mcpServers: { ...oldServers, github: plain() } });
      } else {
        write(old(), { mcpServers: oldServers });
        write(added(), { mcpServers: { github: plain() } });
      }

      const result = await protect();

      expect(result.sharedName.map((s) => [s.client, s.server])).toEqual([[client, 'github']]);
      expect(result.servers.map((s) => s.server)).not.toContain('github');
      expect(servers(added()).github).toEqual(plain());
      expect(await keysUnder(client, 'github')).toEqual(before);
    });
  }
});

describe('p2: with the old-wrapper entry removed, an added entry in the project\'s .mcp.json under its pair is left', () => {
  for (const [label, value] of [['equals', VALUE], ['differs from', OTHER]] as const) {
    it(`p2: left with the project-level reason when its value ${label} the stored one`, async () => {
      await store().storeServerSecrets('claude-code', 'github', { [NAME]: VALUE });
      const before = await keysUnder('claude-code', 'github');
      const file = write(projectMcpJson(), { mcpServers: { github: plain(value) } });
      const text = fs.readFileSync(file, 'utf-8');

      const result = await protect();

      expect(result.unmoved.map((s) => [s.client, s.server, s.reason])).toEqual([[
        'claude-code',
        'github',
        `${NAME} is stored under claude-code/github, and a value from a project-level config is stored only under a name that holds no stored secret`,
      ]]);
      expect(result.servers).toEqual([]);
      expect(fs.readFileSync(file, 'utf-8')).toBe(text);
      expect(await keysUnder('claude-code', 'github')).toEqual(before);
      expect(await store().getBinding('claude-code', 'github')).toBeUndefined();
    });
  }
});

describe('p3: with the old-wrapper entry removed, an added entry in a home config under its pair', () => {
  it('p3: is bound when its value equals the stored one', async () => {
    await store().storeServerSecrets('cursor', 'github', { [NAME]: VALUE });
    const file = write(homeCursor(), { mcpServers: { github: plain(VALUE) } });

    const result = await protect();

    expect(result.servers.map((s) => `${s.client}/${s.server}`)).toEqual(['cursor/github']);
    const binding = await store().getBinding('cursor', 'github');
    expect(binding).toMatchObject({ client: 'cursor', server: 'github', file });
    const entry = servers(file).github;
    expect(entry.command).toBe(WRAPPER_JS);
    expect(entry.args.slice(0, 6)).toEqual(['--server', 'github', '--client', 'cursor', '--binding', binding?.id]);
    expect(await keysUnder('cursor', 'github')).toEqual({ [`mcp/cursor/github/${NAME}`]: VALUE });
  });

  it('p3: is left with the reason that names the stored value when its value differs', async () => {
    await store().storeServerSecrets('cursor', 'github', { [NAME]: VALUE });
    const before = await keysUnder('cursor', 'github');
    const file = write(homeCursor(), { mcpServers: { github: plain(OTHER) } });
    const text = fs.readFileSync(file, 'utf-8');

    const result = await protect();

    expect(result.unmoved.map((s) => [s.client, s.server, s.reason])).toEqual([
      ['cursor', 'github', `${NAME} is stored under cursor/github with another value`],
    ]);
    expect(result.servers).toEqual([]);
    expect(fs.readFileSync(file, 'utf-8')).toBe(text);
    expect(await keysUnder('cursor', 'github')).toEqual(before);
    expect(await store().getBinding('cursor', 'github')).toBeUndefined();
  });
});

describe('p4: an added entry under a new name is bound, and every key under the old-wrapper entry\'s pair is as it was', () => {
  const cases: Array<{ label: string; kept: boolean; added: () => string; client: string }> = [
    { label: 'old entry kept, added entry in .mcp.json', kept: true, added: projectMcpJson, client: 'claude-code' },
    { label: 'old entry kept, added entry in a home config', kept: true, added: homeCursor, client: 'cursor' },
    { label: 'old entry removed, added entry in .mcp.json', kept: false, added: projectMcpJson, client: 'claude-code' },
    { label: 'old entry removed, added entry in a home config', kept: false, added: homeCursor, client: 'cursor' },
  ];
  for (const { label, kept, added, client } of cases) {
    it(`p4: ${label}`, async () => {
      await store().storeServerSecrets('cursor', 'github', { [NAME]: VALUE });
      const before = await keysUnder('cursor', 'github');
      const addedServers = { 'github-two': plain(OTHER) };
      if (kept && added() === homeCursor()) {
        write(homeCursor(), { mcpServers: { legacy: oldEntry('cursor', 'github'), ...addedServers } });
      } else {
        if (kept) write(homeCursor(), { mcpServers: { legacy: oldEntry('cursor', 'github') } });
        write(added(), { mcpServers: addedServers });
      }

      const result = await protect();

      expect(result.servers.map((s) => `${s.client}/${s.server}`)).toEqual([`${client}/github-two`]);
      expect(await store().getBinding(client, 'github-two')).toMatchObject({ client, server: 'github-two', file: added() });
      expect(await keysUnder(client, 'github-two')).toEqual({ [`mcp/${client}/github-two/${NAME}`]: OTHER });
      expect(await keysUnder('cursor', 'github')).toEqual(before);
    });
  }
});

describe('p5: the line for an entry on a wrapper that does not check its binding always ends with what protect-mcp does about it', () => {
  function childEnv(): NodeJS.ProcessEnv {
    return { PATH: process.env.PATH, HOME: home, SECRETLESS_OS_KEYCHAIN: 'off', OPENA2A_TELEMETRY: 'off' };
  }

  function runCli(args: string[], cli: string): string {
    return execFileSync(process.execPath, [cli, ...args], { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'], cwd: project, env: childEnv() });
  }

  /**
   * A copy of this build whose package.json gives a version that is not one,
   * so the CLI run from it cannot read its own version: dist/ copied, the
   * package's node_modules linked. Its cli.js.
   */
  function unversionedBuild(): string {
    const root = path.join(scratch, 'secretless-ai-unversioned');
    fs.cpSync(path.dirname(CLI_PATH), path.join(root, 'dist'), { recursive: true });
    write(path.join(root, 'package.json'), { name: 'secretless-ai', version: 'unreleased' });
    fs.symlinkSync(path.resolve(__dirname, '..', '..', 'node_modules'), path.join(root, 'node_modules'));
    return path.join(root, 'dist', 'cli.js');
  }

  /** The line mcp-status prints for `name`. */
  function lineOf(status: string, name: string): string | undefined {
    return status.split('\n').find((row) => row.startsWith(`    + ${name}: `) || row.startsWith(`    ? ${name}: `));
  }

  it('p5: across every wrapper class, both config kinds and both states of this build\'s own version, never with nothing', () => {
    const unversioned = unversionedBuild();
    const wrappers: Record<string, string> = {
      this: WRAPPER_JS,
      copy: path.join(path.dirname(unversioned), 'mcp-wrapper.js'),
      below: scratchWrapper('below', '0.0.1'),
      same: scratchWrapper('same', THIS_VERSION),
      at: scratchWrapper('at', FIRST_BINDING_VERSION),
      above: scratchWrapper('above', '99.0.0'),
      gone: path.join(scratch, 'gone', 'mcp-wrapper.js'),
      bare: 'secretless-mcp',
    };
    const kinds = { rewritten: 'h', 'not-rewritten': 'p' } as const;
    const entries = (prefix: string) =>
      Object.fromEntries(Object.entries(wrappers).map(([label, wrapper]) => [`${prefix}-${label}`, onWrapper(wrapper, 'cursor', `${prefix}-${label}`)]));
    write(homeCursor(), { mcpServers: entries(kinds.rewritten) });
    write(projectCursor(), { mcpServers: entries(kinds['not-rewritten']) });

    const runs = { read: runCli(['mcp-status'], CLI_PATH), unread: runCli(['mcp-status'], unversioned) };

    const oldLines: Record<string, string[]> = {};
    for (const [state, status] of Object.entries(runs)) {
      for (const [kind, prefix] of Object.entries(kinds)) {
        for (const label of Object.keys(wrappers)) {
          const name = `${prefix}-${label}`;
          const line = lineOf(status, name);
          expect(line, `${state} ${kind} ${label}`).toBeDefined();
          const phrase = [OLD_LINE, UNREAD_LINE].find((p) => line!.includes(p));
          if (phrase === undefined) continue;
          (oldLines[`${state} ${kind}`] ??= []).push(label);
          const ending = line!.slice(line!.indexOf(phrase) + phrase.length);
          expect(ending, `${state} ${kind} ${label}`).not.toBe('');
          if (kind === 'rewritten') {
            expect(REPOINTS.test(ending) || ending === OWN_VERSION_UNREAD, `${state} ${kind} ${label}: ${ending}`).toBe(true);
          } else {
            expect(ending, `${state} ${kind} ${label}`).toBe(NOT_REWRITTEN);
          }
        }
      }
    }
    // Every state and config kind holds such a line: a wrapper below the first
    // version that checks bindings, and one whose version is not read, never
    // check it; one at or above that version always does.
    for (const state of Object.keys(runs)) {
      for (const kind of Object.keys(kinds)) {
        expect(oldLines[`${state} ${kind}`], `${state} ${kind}`).toEqual(expect.arrayContaining(['below', 'gone', 'bare']));
        expect(oldLines[`${state} ${kind}`], `${state} ${kind}`).not.toContain('at');
        expect(oldLines[`${state} ${kind}`], `${state} ${kind}`).not.toContain('above');
      }
    }
  }, 60_000);
});
