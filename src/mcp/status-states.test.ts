import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach, vi } from 'vitest';
import { execFileSync, spawnSync } from 'child_process';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
// Read from the module object, so a build that lacks one of these functions
// fails the cells that call it and runs the others.
import * as protect from './protect';
import { McpVault, commandDigest } from './vault';
import type { McpBinding } from './vault';
import { discoverMcpConfigsDetailed, thisBuildWrapperPath } from './discover';
import type { McpConfigFile } from './discover';
import { runMcpStatus } from '../commands/mcp';
import { builtCommand, sourceCommand } from './printed-command.test-support';

/**
 * mcp-status reports each entry that runs through the wrapper by two things:
 * its state, which is where the binding stored for the pair it reads points
 * relative to it ((a) no binding, (b) another entry's place, (c) its own
 * place with no id or another one, (d) its own place and id with another
 * command, (e) bound), and whether the wrapper starts it from the directory
 * mcp-status runs in, which the wrapper's own checks compute. Under an entry
 * in a config protect-mcp rewrites, it names what protect-mcp then does for
 * its binding. An entry on a wrapper that does not check bindings gets no
 * computed start clause. mcp-status writes nothing.
 *
 * The wrapper and the CLI run from the build (`dist/`); protect-mcp runs in
 * this process with no home directory given, as the command runs it. Values
 * are assembled at run time and are not credentials.
 */

const CLI_PATH = path.resolve(__dirname, '..', '..', 'dist', 'cli.js');
const WRAPPER_JS = path.resolve(__dirname, '..', '..', 'dist', 'mcp-wrapper.js');
const THIS_VERSION: string = JSON.parse(fs.readFileSync(path.resolve(__dirname, '..', '..', 'package.json'), 'utf-8')).version;
const NAME = ['MY', 'SERVICE', 'API', 'KEY'].join('_');
const VALUE = ['stand', 'in', 'value', String(process.pid)].join('-');
const NOT_STARTED = 'so the wrapper does not start it';
const PROTECT = `\`${builtCommand('protect-mcp')}\``;
/** The same command in a reason protect-mcp gives when it runs in this process. */
const PROTECT_HERE = `\`${sourceCommand('protect-mcp')}\``;

interface Dirs {
  home: string;
  project: string;
  away: string;
  scratch: string;
  bin: string;
}

let dirs: Dirs;
let saved: Record<'HOME' | 'USER' | 'PATH', string | undefined>;

/** Fresh directories, and HOME, USER and PATH as the commands this test starts get them. */
function enter(): void {
  const make = (label: string) => fs.mkdtempSync(path.join(os.tmpdir(), `secretless-status-${label}-`));
  dirs = { home: make('home'), project: make('proj'), away: make('away'), scratch: make('scratch'), bin: make('bin') };
  // Never run: a keychain backend is not built where `local` is configured.
  fs.writeFileSync(path.join(dirs.bin, 'secret-tool'), '#!/bin/sh\nexit 1\n', { mode: 0o755 });
  // The local store's key is made from HOME and USER: this process and the
  // commands it starts get the same ones.
  saved = { HOME: process.env.HOME, USER: process.env.USER, PATH: process.env.PATH };
  process.env.HOME = dirs.home;
  delete process.env.USER;
  process.env.PATH = `${dirs.bin}${path.delimiter}${saved.PATH ?? ''}`;
  // As `backend set local` leaves it: `local` is the encrypted file.
  write(path.join(dirs.home, '.secretless-ai', 'config.json'), { backend: 'local' });
}

function leave(): void {
  for (const [name, value] of Object.entries(saved)) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
  for (const dir of Object.values(dirs)) fs.rmSync(dir, { recursive: true, force: true });
}

function write(fullPath: string, content: unknown): string {
  fs.mkdirSync(path.dirname(fullPath), { recursive: true });
  fs.writeFileSync(fullPath, JSON.stringify(content, null, 2));
  return fullPath;
}

function childEnv(): NodeJS.ProcessEnv {
  return { PATH: process.env.PATH, HOME: dirs.home, SECRETLESS_OS_KEYCHAIN: 'off', OPENA2A_TELEMETRY: 'off' };
}

/** A stub server: writes its env to `sentinel`, so a test sees it started. */
function stubArgs(sentinel: string): string[] {
  return ['-e', `require('fs').writeFileSync(${JSON.stringify(sentinel)}, JSON.stringify(process.env))`];
}

/** The built wrapper started with these args in `cwd`, as a client starts an entry there. */
function startWrapper(args: string[], cwd: string) {
  return spawnSync(process.execPath, [WRAPPER_JS, ...args], { cwd, encoding: 'utf-8', env: childEnv() });
}

function runCli(args: string[], cwd: string): string {
  return execFileSync(process.execPath, [CLI_PATH, ...args], { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'], cwd, env: childEnv() });
}

const homeConfig = () => path.join(dirs.home, '.cursor', 'mcp.json');

function split(args: string[]): { own: string[]; child: string[] } {
  const at = args.indexOf('--');
  return { own: args.slice(0, at), child: args.slice(at + 1) };
}

/** The --binding value in a wrapper's own args. */
function idOf(args: string[]): string {
  const { own } = split(args);
  return own[own.indexOf('--binding') + 1];
}

/** A wrapper's own args with its --binding flag and value removed, then its command. */
function withoutBinding(args: string[]): string[] {
  const { own, child } = split(args);
  const at = own.indexOf('--binding');
  return [...own.slice(0, at), ...own.slice(at + 2), '--', ...child];
}

function otherId(id: string): string {
  let next = crypto.randomBytes(16).toString('hex');
  while (next === id) next = crypto.randomBytes(16).toString('hex');
  return next;
}

/** A wrapped entry that reads its own pair, with no binding. */
function wrapped(command: string, name: string, child: string[] = [process.execPath, '-e', '0']) {
  return { command, args: ['--server', name, '--client', 'cursor', '--', ...child] };
}

/** A scratch wrapper file that reads `version` as an installed copy does (wrapper-version.json beside it). */
function scratchWrapper(label: string, version: string): string {
  const file = path.join(dirs.scratch, label, 'mcp-wrapper.js');
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, '// a scratch wrapper: never started\n');
  fs.writeFileSync(path.join(path.dirname(file), 'wrapper-version.json'), JSON.stringify({ version }));
  return file;
}

/** The line mcp-status prints for `name`, and the fix line under it, when there is one. */
function linesOf(status: string, name: string): { line?: string; fix?: string } {
  const rows = status.split('\n');
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const at = rows.findIndex((row) => new RegExp(`^ {4}[+?] ${escaped}: `).test(row));
  if (at === -1) return {};
  const next = rows[at + 1];
  return next !== undefined && /^ {6}\S/.test(next) ? { line: rows[at], fix: next } : { line: rows[at] };
}

/** Every file and directory under `root`, by path from it, with a digest of each file's bytes. */
function snapshot(root: string): Record<string, string> {
  const out: Record<string, string> = {};
  const walk = (dir: string) => {
    if (!fs.existsSync(dir)) return;
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      const rel = path.relative(root, full);
      if (entry.isDirectory()) {
        out[`${rel}/`] = 'dir';
        walk(full);
      } else {
        out[rel] = crypto.createHash('sha256').update(fs.readFileSync(full)).digest('hex');
      }
    }
  };
  walk(root);
  return out;
}

/** The bytes of each file, by path. */
function filesOf(paths: string[]): Record<string, string> {
  return Object.fromEntries(paths.map((p) => [p, fs.readFileSync(p, 'utf-8')]));
}

// ---------------------------------------------------------------------------
// One machine with an entry in every state, reported from the project and
// from a directory with no project-level config.
// ---------------------------------------------------------------------------

describe('mcp-status over every state, from the project and from elsewhere', () => {
  const sentinel = (name: string) => path.join(dirs.project, `${name}-started.json`);
  let file: string;
  let mcpJson: string;
  let cursorProject: string;
  let kappaPair: string;
  let ids: Record<string, string>;
  let entries: Record<string, { command: string; args: string[] }>;
  let inProject: string;
  let away: string;
  let storeBefore: Record<string, string>;
  let storeAfter: Record<string, string>;
  let configsBefore: Record<string, string>;
  let configsAfter: Record<string, string>;

  beforeAll(async () => {
    enter();
    const stub = (name: string) => ({ command: process.execPath, args: stubArgs(sentinel(name)), env: { [NAME]: VALUE } });
    file = write(homeConfig(), {
      mcpServers: {
        alpha: stub('alpha'),
        beta: stub('beta'),
        gamma: stub('gamma'),
        lambda: stub('lambda'),
        // Bound by protect-mcp with no secret stored under its pair.
        omega: wrapped(WRAPPER_JS, 'omega', [process.execPath, ...stubArgs(sentinel('omega'))]),
      },
    });
    mcpJson = write(path.join(dirs.project, '.mcp.json'), { mcpServers: { kappa: stub('kappa') } });
    await protect.protectMcp({ projectDir: dirs.project, wrapperPath: WRAPPER_JS });

    const config = JSON.parse(fs.readFileSync(file, 'utf-8'));
    const m = config.mcpServers;
    const project = JSON.parse(fs.readFileSync(mcpJson, 'utf-8'));
    const kappa = project.mcpServers.kappa;
    ids = { alpha: idOf(m.alpha.args), beta: idOf(m.beta.args), lambda: idOf(m.lambda.args), omega: idOf(m.omega.args), kappa: idOf(kappa.args) };
    const kappaReads = split(kappa.args).own;
    kappaPair = `${kappaReads[kappaReads.indexOf('--client') + 1]}/kappa`;
    // (c) at the record's own place: another id, in a home config and in .mcp.json.
    m.beta.args = m.beta.args.map((arg: string) => (arg === ids.beta ? otherId(ids.beta) : arg));
    kappa.args = kappa.args.map((arg: string) => (arg === ids.kappa ? otherId(ids.kappa) : arg));
    // (d) its command changed since it was bound.
    m.gamma.args = [...m.gamma.args, 'extra'];
    // (b) reads alpha's pair and carries no id.
    m.delta = { command: WRAPPER_JS, args: withoutBinding(m.alpha.args) };
    // (a) a pair with no binding.
    m.epsilon = wrapped(WRAPPER_JS, 'epsilon', [process.execPath, ...stubArgs(sentinel('epsilon'))]);
    // (b) copies: of alpha with its command, of alpha with another command,
    // and of the project binding of kappa (with kappa's id before it changed).
    m.gamma2 = { ...m.alpha };
    m.gamma3 = { ...m.alpha, args: [...m.alpha.args, 'extra'] };
    m['kappa-copy'] = { ...JSON.parse(fs.readFileSync(mcpJson, 'utf-8')).mcpServers.kappa };
    // Wrappers this build does not start from: one that reads a version below
    // the first that checks bindings, one whose file is gone, and one that
    // reads this build's version.
    m.mu = wrapped(scratchWrapper('old', '0.0.1'), 'mu');
    m.nu = wrapped(path.join(dirs.scratch, 'gone', 'mcp-wrapper.js'), 'nu');
    m.omicron = wrapped(scratchWrapper('same', THIS_VERSION), 'omicron');
    write(file, config);
    write(mcpJson, project);
    // A project-level config protect-mcp does not rewrite.
    cursorProject = write(path.join(dirs.project, '.cursor', 'mcp.json'), {
      mcpServers: {
        'lambda-copy': { ...m.lambda },
        eta: { command: WRAPPER_JS, args: withoutBinding(m.alpha.args) },
        zeta: wrapped(WRAPPER_JS, 'zeta', [process.execPath, ...stubArgs(sentinel('zeta'))]),
        xi: { command: 'secretless-mcp', args: ['--server', 'xi', '--client', 'cursor', '--', 'npx', 'xi-mcp'] },
      },
    });
    entries = {
      ...JSON.parse(fs.readFileSync(file, 'utf-8')).mcpServers,
      ...JSON.parse(fs.readFileSync(mcpJson, 'utf-8')).mcpServers,
      ...JSON.parse(fs.readFileSync(cursorProject, 'utf-8')).mcpServers,
    };

    const store = path.join(dirs.home, '.secretless-ai');
    storeBefore = snapshot(store);
    configsBefore = filesOf([file, mcpJson, cursorProject]);
    inProject = runCli(['mcp-status'], dirs.project);
    away = runCli(['mcp-status'], dirs.away);
    storeAfter = snapshot(store);
    configsAfter = filesOf([file, mcpJson, cursorProject]);
  }, 120_000);

  afterAll(() => leave());

  const copyFile = () => path.join(fs.realpathSync(dirs.project), '.cursor', 'mcp.json');
  const boundTo = (server: string, where: string) => `server "${server}" in ${where}`;
  const elsewhereReason = (protect = PROTECT) =>
    `the secrets stored under cursor/alpha are bound to ${boundTo('alpha', file)}. To run this server as well, add it again under a new name with its values and run ${protect}.`;

  it('X2-a: each state reads as its own line, from the record and the entry\'s place', () => {
    expect(linesOf(inProject, 'alpha').line).toBe('    + alpha: protected and bound');
    expect(linesOf(inProject, 'beta').line).toBe(`    ? beta: protected, but it does not carry the binding stored for it, ${NOT_STARTED}`);
    expect(linesOf(inProject, 'gamma').line).toBe(`    ? gamma: protected, but its command or arguments changed since it was bound, ${NOT_STARTED}`);
    expect(linesOf(inProject, 'delta').line).toBe(`    ? delta: the secrets it reads are bound to the entry for ${boundTo('alpha', file)}, ${NOT_STARTED}`);
    expect(linesOf(inProject, 'epsilon').line).toBe(`    ? epsilon: protected, not bound, ${NOT_STARTED}`);
    expect(linesOf(inProject, 'zeta').line).toBe(
      `    ? zeta: runs through the wrapper from a config protect-mcp does not rewrite, so it is never bound and the wrapper does not start it`,
    );
  });

  it('s1: an entry with no id in .cursor/mcp.json reads (b) where its pair is bound elsewhere, and the fifth state where it is not', () => {
    expect(linesOf(inProject, 'eta').line).toBe(`    ? eta: the secrets it reads are bound to the entry for ${boundTo('alpha', file)}, ${NOT_STARTED}`);
    expect(linesOf(inProject, 'zeta').line).toContain('runs through the wrapper from a config protect-mcp does not rewrite');
    // protect-mcp does not rewrite the file, so no line under these names what it does.
    expect(linesOf(inProject, 'eta').fix).toBeUndefined();
    expect(linesOf(inProject, 'zeta').fix).toBeUndefined();
  });

  it('s2: an entry at its binding\'s own place with another id reads (c), and no line names that place as another entry', () => {
    expect(linesOf(inProject, 'beta').line).toBe(`    ? beta: protected, but it does not carry the binding stored for it, ${NOT_STARTED}`);
    expect(linesOf(inProject, 'kappa').line).toBe(`    ? kappa: protected, but it does not carry the binding stored for it, ${NOT_STARTED}`);
    for (const status of [inProject, away]) {
      expect(status).not.toContain(`entry for ${boundTo('beta', file)}`);
    }
    expect(inProject).not.toContain(`entry for ${boundTo('kappa', mcpJson)}, ${NOT_STARTED}`);
    expect(linesOf(inProject, 'kappa-copy').line).toContain(`entry for ${boundTo('kappa', mcpJson)}`);
  });

  it('s3: a home-record copy in <project>/.cursor/mcp.json, from the project, is (b) with the copy-found refusal, and its launch exits 1', () => {
    const appears = `its binding also appears in ${copyFile()}`;
    expect(linesOf(inProject, 'lambda-copy').line).toBe(
      `    ? lambda-copy: carries the binding of the entry for ${boundTo('lambda', file)}, but ${appears}, ${NOT_STARTED}`,
    );
    expect(linesOf(inProject, 'lambda').line).toBe(`    ? lambda: protected and bound, but ${appears}, ${NOT_STARTED}`);
    fs.rmSync(sentinel('lambda'), { force: true });
    expect(startWrapper(entries['lambda-copy'].args, dirs.project).status).toBe(1);
    expect(fs.existsSync(sentinel('lambda'))).toBe(false);
  });

  it('s5: an entry on a wrapper that does not check bindings, or whose version is not read, gets no computed start clause', () => {
    const repoints = "; protect-mcp re-points it to this version's wrapper";
    expect(linesOf(inProject, 'mu').line).toBe(`    ? mu: runs through a wrapper that does not check its binding${repoints}`);
    expect(linesOf(inProject, 'nu').line).toBe(`    ? nu: runs through a wrapper whose version could not be read${repoints}`);
    // In a config protect-mcp does not rewrite, nothing re-points it.
    expect(linesOf(inProject, 'xi').line).toBe('    ? xi: runs through a wrapper whose version could not be read');
    for (const name of ['mu', 'nu', 'xi']) {
      expect(linesOf(inProject, name).line).not.toMatch(/starts? it|not bound|bound to/);
    }
    // A wrapper that reads this build's version runs this build's checks.
    expect(linesOf(inProject, 'omicron').line).toBe(`    ? omicron: protected, not bound, ${NOT_STARTED}`);
  });

  it('X2-d: a home entry with no id whose pair is bound elsewhere reads (b), and its fix line is protect-mcp\'s bound-elsewhere reason', () => {
    expect(linesOf(inProject, 'delta')).toEqual({
      line: `    ? delta: the secrets it reads are bound to the entry for ${boundTo('alpha', file)}, ${NOT_STARTED}`,
      fix: `      ${PROTECT} leaves it not bound: ${elsewhereReason()}`,
    });
  });

  it('the start clause holds the wrapper\'s empty-pair refusal and a copy\'s changed command', () => {
    expect(linesOf(inProject, 'omega').line).toBe(`    ? omega: protected and bound, but no secret is stored for the pair it reads, ${NOT_STARTED}`);
    expect(linesOf(inProject, 'gamma3').line).toBe(
      `    ? gamma3: carries the binding of the entry for ${boundTo('alpha', file)}, but its command or arguments are not the ones that entry was bound with, ${NOT_STARTED}`,
    );
    expect(linesOf(inProject, 'gamma2').line).toBe(
      `    ? gamma2: carries the binding of the entry for ${boundTo('alpha', file)}, so the wrapper starts it with that entry's secrets`,
    );
  });

  it('X2-b: from each directory, a line says the entry starts exactly when launching its args there writes the sentinel', () => {
    const agree = (cwd: string, status: string, names: string[]) => {
      const exits: Record<string, number | null> = {};
      for (const name of names) {
        for (const s of ['alpha', 'beta', 'gamma', 'lambda', 'omega', 'epsilon', 'kappa', 'zeta']) fs.rmSync(sentinel(s), { force: true });
        const res = startWrapper(entries[name].args, cwd);
        exits[name] = res.status;
        const line = linesOf(status, name).line;
        expect(line, `${name} has a line`).toBeDefined();
        const starts = /^ {4}\+ /.test(line ?? '') || /so the wrapper starts it/.test(line ?? '');
        expect(starts, `${name}: "${line}" against exit ${res.status}`).toBe(res.status === 0);
        expect(/does not start/.test(line ?? ''), `${name}: "${line}" against exit ${res.status}`).toBe(res.status === 1);
        const written = ['alpha', 'beta', 'gamma', 'lambda', 'omega', 'epsilon', 'kappa', 'zeta'].some((s) => fs.existsSync(sentinel(s)));
        expect(written, `${name}: a sentinel against exit ${res.status}`).toBe(res.status === 0);
      }
      return exits;
    };
    const home = ['alpha', 'beta', 'gamma', 'lambda', 'omega', 'delta', 'epsilon', 'gamma2', 'gamma3', 'kappa-copy'];
    expect(agree(dirs.project, inProject, [...home, 'kappa', 'lambda-copy', 'eta', 'zeta'])).toEqual({
      alpha: 0, beta: 1, gamma: 1, lambda: 1, omega: 1, delta: 1, epsilon: 1, gamma2: 0, gamma3: 1, 'kappa-copy': 0,
      kappa: 1, 'lambda-copy': 1, eta: 1, zeta: 1,
    });
    // Away from the project: the copy of lambda is not visible, and kappa's
    // binding is to the project's directory.
    expect(agree(dirs.away, away, home)).toEqual({
      alpha: 0, beta: 1, gamma: 1, lambda: 0, omega: 1, delta: 1, epsilon: 1, gamma2: 0, gamma3: 1, 'kappa-copy': 1,
    });
  }, 120_000);

  it('s6: an mcp-status run leaves the store, every key in it, and every discovered config byte-identical', () => {
    expect(Object.keys(storeBefore).length).toBeGreaterThan(1);
    expect(storeAfter).toEqual(storeBefore);
    expect(configsAfter).toEqual(configsBefore);
  });

  it('no line carries a binding id, and none names mcp-forget', () => {
    for (const status of [inProject, away]) {
      for (const id of Object.values(ids)) expect(status).not.toContain(id);
      expect(status).not.toContain('mcp-forget');
    }
  });

  it('each fix line mcp-status names is what protect-mcp then does, and a bound entry has none', async () => {
    const expected: Record<string, string | undefined> = {
      alpha: undefined,
      lambda: undefined,
      omega: undefined,
      beta: `      ${PROTECT} writes its binding into it again.`,
      gamma: `      ${PROTECT} binds it again with its command as it is now.`,
      delta: `      ${PROTECT} leaves it not bound: ${elsewhereReason()}`,
      epsilon: `      ${PROTECT} binds it.`,
      gamma2: `      ${PROTECT} replaces the binding of ${boundTo('alpha', file)}; this entry then no longer starts.`,
      // protect-mcp replaces alpha's binding at gamma2, so this copy then carries an id the binding no longer has.
      gamma3: `      ${PROTECT} leaves it not bound: ${elsewhereReason()}`,
      'kappa-copy': `      ${PROTECT} reports it as a copy of ${boundTo('kappa', mcpJson)} and writes nothing for it.`,
      mu: `      ${PROTECT} binds it.`,
      nu: `      ${PROTECT} binds it.`,
      omicron: `      ${PROTECT} binds it.`,
      kappa: `      ${PROTECT} leaves it not bound: its binding does not match the one stored for ${kappaPair}. If this entry is yours, add the server again under a new name with its values, remove this entry, and run ${PROTECT}.`,
    };
    for (const [name, fix] of Object.entries(expected)) expect(linesOf(inProject, name).fix, name).toBe(fix);
    // From elsewhere, the plans of the home entries are the same.
    for (const name of Object.keys(expected).filter((n) => n !== 'kappa')) expect(linesOf(away, name).fix, `${name} away`).toBe(expected[name]);

    const result = await protect.protectMcp({ projectDir: dirs.project, wrapperPath: WRAPPER_JS });
    const find = <T extends { server: string }>(list: T[], name: string) => list.filter((entry) => entry.server === name);
    const outcome = (name: string) => ({
      bound: find(result.bound, name).length,
      rebound: find(result.rebound, name).map((entry) => (entry.outOfDate ? 'out-of-date' : 'command')),
      unbound: find(result.unbound, name).map((entry) => entry.reason),
      copies: find(result.copies, name).map((entry) => (entry.replaced ? `replaced ${entry.boundTo.server}` : `copy of ${entry.boundTo.server}`)),
    });
    const nothing = { bound: 0, rebound: [], unbound: [], copies: [] };
    expect(outcome('alpha')).toEqual(nothing);
    expect(outcome('lambda')).toEqual(nothing);
    expect(outcome('omega')).toEqual(nothing);
    expect(outcome('beta')).toEqual({ ...nothing, rebound: ['out-of-date'] });
    expect(outcome('gamma')).toEqual({ ...nothing, rebound: ['command'] });
    expect(outcome('delta')).toEqual({ ...nothing, unbound: [elsewhereReason(PROTECT_HERE)] });
    expect(outcome('epsilon')).toEqual({ ...nothing, bound: 1 });
    expect(outcome('gamma2')).toEqual({ ...nothing, copies: ['replaced alpha'] });
    expect(outcome('gamma3')).toEqual({ ...nothing, unbound: [elsewhereReason(PROTECT_HERE)] });
    expect(outcome('kappa-copy')).toEqual({ ...nothing, copies: ['copy of kappa'] });
    for (const name of ['mu', 'nu', 'omicron']) expect(outcome(name), name).toEqual({ ...nothing, bound: 1 });
    // The reason mcp-status's fix line names, with its command as protect-mcp in this process prints it.
    expect(outcome('kappa').unbound).toEqual([expected.kappa?.slice(`      ${PROTECT} leaves it not bound: `.length).split(PROTECT).join(PROTECT_HERE)]);
    // Nothing is planned or written for the config protect-mcp does not rewrite.
    for (const name of ['lambda-copy', 'eta', 'zeta', 'xi']) expect(outcome(name), name).toEqual(nothing);
    expect(fs.readFileSync(cursorProject, 'utf-8')).toBe(configsBefore[cursorProject]);
  }, 120_000);
});

// ---------------------------------------------------------------------------
// Cells with a machine of their own.
// ---------------------------------------------------------------------------

describe('the state function, the start clause, and what mcp-status leaves', () => {
  beforeEach(() => enter());
  afterEach(() => {
    vi.restoreAllMocks();
    leave();
  });

  it('X2-a: bindingState gives each cell its state, first match winning, with location compared by real path', () => {
    const homeFile = write(path.join(dirs.home, '.cursor', 'mcp.json'), { mcpServers: {} });
    const otherFile = write(path.join(dirs.home, '.claude', 'settings.json'), { mcpServers: {} });
    const projectFile = write(path.join(dirs.project, '.cursor', 'mcp.json'), { mcpServers: {} });
    const child = ['node', 'server.js'];
    const id = 'a'.repeat(32);
    const record = (over: Partial<McpBinding> = {}): McpBinding => ({
      schema: 1, id, scope: 'home', file: homeFile, client: 'cursor', server: 'alpha',
      commandDigest: commandDigest(child[0], child.slice(1)), boundAt: '2026-10-24T00:00:00.000Z', boundBy: THIS_VERSION, ...over,
    });
    const entry = (binding: string | undefined, command = child) => ({
      name: 'alpha',
      args: ['--server', 'alpha', '--client', 'cursor', ...(binding === undefined ? [] : ['--binding', binding]), '--', ...command],
    });
    const home = { filePath: homeFile };
    const linkDir = path.join(dirs.scratch, 'cursor-link');
    fs.symlinkSync(path.dirname(homeFile), linkDir, 'dir');

    const cells: Array<[string, unknown, unknown]> = [
      ['(a) no record, a config protect-mcp rewrites', protect.bindingState(undefined, home, entry(id)), { state: 'unbound' }],
      ['(a) no record, .cursor/mcp.json in the project', protect.bindingState(undefined, { filePath: projectFile, projectPath: path.join('.cursor', 'mcp.json') }, entry(undefined)), { state: 'not-rewritten' }],
      ['(b) another file, the record\'s id', protect.bindingState(record({ file: otherFile }), home, entry(id)), { state: 'elsewhere', carriesRecordId: true }],
      ['(b) another file, no id', protect.bindingState(record({ file: otherFile }), home, entry(undefined)), { state: 'elsewhere', carriesRecordId: false }],
      ['(b) another server name', protect.bindingState(record({ server: 'beta' }), home, entry(id)), { state: 'elsewhere', carriesRecordId: true }],
      ['(b) another project key', protect.bindingState(record({ projectKey: '/work/app' }), home, entry(id)), { state: 'elsewhere', carriesRecordId: true }],
      ['(b) another file and another command', protect.bindingState(record({ file: otherFile }), home, entry(id, ['node', 'other.js'])), { state: 'elsewhere', carriesRecordId: true }],
      ['(b) in .cursor/mcp.json, the record\'s id', protect.bindingState(record(), { filePath: projectFile, projectPath: path.join('.cursor', 'mcp.json') }, entry(id)), { state: 'elsewhere', carriesRecordId: true }],
      ['(c) its place, no id', protect.bindingState(record(), home, entry(undefined)), { state: 'stale-id' }],
      ['(c) its place, another id', protect.bindingState(record(), home, entry('b'.repeat(32))), { state: 'stale-id' }],
      ['(c) its place, another id and another command', protect.bindingState(record(), home, entry('b'.repeat(32), ['node', 'other.js'])), { state: 'stale-id' }],
      ['(d) its place and id, another command', protect.bindingState(record(), home, entry(id, ['node', 'other.js'])), { state: 'command-changed' }],
      ['(e) its place, id and command', protect.bindingState(record(), home, entry(id)), { state: 'bound' }],
      ['(e) its file reached through a symlinked directory', protect.bindingState(record(), { filePath: path.join(linkDir, 'mcp.json') }, entry(id)), { state: 'bound' }],
    ];
    for (const [cell, state, want] of cells) expect(state, cell).toMatchObject(want as object);
  });

  it('s4: the same copy, from a directory whose walk does not reach it, is (b) and starts, and its launch there writes the sentinel', async () => {
    const { checkStart } = await import('./start-check.js');
    const started = path.join(dirs.project, 'lambda-started.json');
    const file = write(homeConfig(), { mcpServers: { lambda: { command: process.execPath, args: stubArgs(started), env: { [NAME]: VALUE } } } });
    await protect.protectMcp({ projectDir: dirs.project, wrapperPath: WRAPPER_JS });
    const lambda = JSON.parse(fs.readFileSync(file, 'utf-8')).mcpServers.lambda;
    write(path.join(dirs.project, '.cursor', 'mcp.json'), { mcpServers: { 'lambda-copy': { ...lambda } } });

    const copyConfig = discoverMcpConfigsDetailed(dirs.home, dirs.project).configs.find((c: McpConfigFile) => c.projectPath !== undefined);
    const copy = copyConfig?.servers.find((s) => s.name === 'lambda-copy');
    expect(copy).toBeDefined();
    const vault = new McpVault({ storeDir: path.join(dirs.home, '.secretless-ai', 'mcp-vault'), backendType: 'local' });
    const record = await vault.getBinding('cursor', 'lambda');
    expect(protect.bindingState(record, copyConfig as McpConfigFile, copy as { name: string; args: string[] })).toMatchObject({ state: 'elsewhere', carriesRecordId: true });
    const { child } = split(lambda.args);
    const launch = { client: 'cursor', server: 'lambda', binding: idOf(lambda.args), command: child[0], args: child.slice(1) };
    expect(await checkStart(vault, launch, { startDir: dirs.away })).toMatchObject({ starts: true });
    expect(await checkStart(vault, launch, { startDir: dirs.project })).toMatchObject({ starts: false, place: { refused: 'copy-found' } });

    expect(startWrapper(lambda.args, dirs.away).status).toBe(0);
    expect(fs.existsSync(started)).toBe(true);
    fs.rmSync(started);
    expect(startWrapper(lambda.args, dirs.project).status).toBe(1);
    expect(fs.existsSync(started)).toBe(false);
  }, 60_000);

  it('X2-c: a bound .mcp.json reached through a symlinked spelling of its directory reads bound, not another entry', async () => {
    const real = fs.realpathSync(dirs.project);
    const link = path.join(dirs.scratch, 'project-link');
    fs.symlinkSync(real, link, 'dir');
    const started = path.join(real, 'kappa-started.json');
    write(path.join(real, '.mcp.json'), { mcpServers: { kappa: { command: process.execPath, args: stubArgs(started), env: { [NAME]: VALUE } } } });
    await protect.protectMcp({ projectDir: real, wrapperPath: thisBuildWrapperPath() });

    // In this process: a spawned process's directory is the physical path.
    vi.spyOn(process, 'cwd').mockReturnValue(link);
    const lines: string[] = [];
    vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
      lines.push(args.join(' '));
    });
    await runMcpStatus();
    const out = `${lines.join('\n')}\n`;
    expect(out).toContain(`claude-code (.mcp.json)\n    + kappa: protected and bound\n`);
    expect(out).not.toContain('carries the binding of the entry for');
    expect(out).not.toContain('bound to the entry for');
  }, 60_000);

  it('s6: mcp-status builds no store where the local store\'s directory does not exist', () => {
    write(homeConfig(), { mcpServers: { omega: wrapped(WRAPPER_JS, 'omega') } });
    const root = path.join(dirs.home, '.secretless-ai');
    const before = snapshot(root);
    const status = runCli(['mcp-status'], dirs.project);
    expect(fs.existsSync(path.join(root, 'mcp-vault'))).toBe(false);
    expect(snapshot(root)).toEqual(before);
    expect(linesOf(status, 'omega').line).toBe(`    ? omega: protected, not bound, ${NOT_STARTED}`);
  });

  it('with no local store yet, the fix line is the plan protect-mcp then carries out: it binds the entry', async () => {
    write(homeConfig(), { mcpServers: { omega: wrapped(WRAPPER_JS, 'omega') } });
    const status = runCli(['mcp-status'], dirs.project);
    expect(linesOf(status, 'omega').fix).toBe(`      ${PROTECT} binds it.`);
    const result = await protect.protectMcp({ projectDir: dirs.project, wrapperPath: WRAPPER_JS });
    expect(result.bound.map((entry) => entry.server)).toEqual(['omega']);
  });
});
