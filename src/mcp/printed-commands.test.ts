import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { installWrapper } from './install-wrapper';
import { WRAPPER_VERSION_FILE } from './wrapper-version';
import { runMcpStatus, runProtectMcp } from '../commands/mcp';
import { VERSION } from '../commands/utils';
import { pathFormOf } from '../hook-prefix';

/**
 * Every command a wrapper refusal, protect-mcp and mcp-status print names the
 * build that printed it: npx runs a name given without a version from the
 * first copy npm finds, which may be an earlier build that does not do what
 * the line says. Each command printed is also a command the same tree
 * registers.
 *
 * The CLI runs in this process with HOME set to a scratch directory and the
 * local backend configured; the wrapper runs from a copy installed the way
 * earlier versions installed it, with no package.json above it. The built CLI
 * and wrapper under dist/ name their node binary and CLI script, and each
 * command they print is run as printed. Values are assembled at run time and
 * are not credentials.
 */

const ROOT = path.resolve(__dirname, '..', '..');
const CLI_PATH = path.join(ROOT, 'dist', 'cli.js');
const WRAPPER_JS = path.join(ROOT, 'dist', 'mcp-wrapper.js');
const CLI_SOURCE = fs.readFileSync(path.join(ROOT, 'src', 'cli.ts'), 'utf-8');
const NAME = ['MY', 'SERVICE', 'API', 'KEY'].join('_');
const VALUE = ['stand', 'in', 'value', String(process.pid)].join('-');

/**
 * A command a line names, in each form a build has printed: npx with or
 * without a version, or a node binary and a CLI script as two quoted paths;
 * then its subcommand.
 */
const COMMAND = /(npx secretless-ai(?:@[^\s`']+)?|'(?:[^']|'\\'')*' '(?:[^']|'\\'')*') ([a-z][a-z-]*)/g;

function commandsIn(text: string): Array<{ command: string; verb: string }> {
  return [...text.matchAll(COMMAND)].map((m) => ({ command: m[0], verb: m[2] }));
}

let home: string;
let project: string;
let bin: string;
let saved: Record<'HOME' | 'USER' | 'PATH', string | undefined>;

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-printed-home-'));
  project = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-printed-proj-'));
  bin = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-printed-bin-'));
  // Never run: a keychain backend is not built where `local` is configured.
  fs.writeFileSync(path.join(bin, 'secret-tool'), '#!/bin/sh\nexit 1\n', { mode: 0o755 });
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
  for (const dir of [home, project, bin]) fs.rmSync(dir, { recursive: true, force: true });
});

function write(fullPath: string, content: unknown): string {
  fs.mkdirSync(path.dirname(fullPath), { recursive: true });
  fs.writeFileSync(fullPath, typeof content === 'string' ? content : JSON.stringify(content, null, 2));
  return fullPath;
}

function childEnv(): NodeJS.ProcessEnv {
  return { PATH: process.env.PATH, HOME: home, SECRETLESS_OS_KEYCHAIN: 'off', OPENA2A_TELEMETRY: 'off' };
}

/** A server with a secret in its env, not yet protected. */
const plain = () => ({ command: process.execPath, args: ['-e', 'x'], env: { [NAME]: VALUE } });

/** A command of the CLI in this process, from the project directory, with what it prints. */
async function run(command: () => Promise<number>): Promise<string> {
  const lines: string[] = [];
  const capture = (...parts: unknown[]) => { lines.push(parts.map(String).join(' ')); };
  const log = vi.spyOn(console, 'log').mockImplementation(capture);
  const error = vi.spyOn(console, 'error').mockImplementation(capture);
  const cwd = vi.spyOn(process, 'cwd').mockReturnValue(project);
  try {
    expect(await command()).toBe(0);
  } finally {
    log.mockRestore();
    error.mockRestore();
    cwd.mockRestore();
  }
  return lines.join('\n');
}

/**
 * A wrapper copy installed the way earlier versions installed it, started for
 * an entry that carries no binding: the refusal, then the fix line.
 */
function refusedByInstalledCopy(prepare: (binDir: string) => void = () => {}) {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-printed-data-'));
  try {
    const wrapper = installWrapper(dataDir);
    prepare(path.dirname(wrapper.args[0]));
    // The store's directory exists, so the wrapper reaches its binding check.
    fs.mkdirSync(path.join(home, '.secretless-ai', 'mcp-vault'), { recursive: true });
    const res = spawnSync(
      process.execPath,
      [wrapper.args[0], '--server', 'github', '--client', 'cursor', '--', process.execPath, '-e', 'x'],
      { cwd: project, encoding: 'utf-8', env: childEnv() },
    );
    expect(res.status).toBe(1);
    return res.stderr;
  } finally {
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
}

describe('X4-2: every printed command names the exact version of the build that prints it', () => {
  it('every command protect-mcp and mcp-status print is `npx secretless-ai@<VERSION> <cmd>`, and <cmd> is a registered command', async () => {
    // An exposed home server, a project-level config with a value, and a home
    // config that does not parse; then protect-mcp, then the bound entry with
    // its binding taken out.
    const cursor = write(path.join(home, '.cursor', 'mcp.json'), { mcpServers: { github: plain() } });
    write(path.join(project, '.cursor', 'mcp.json'), { mcpServers: { local: plain() } });
    write(path.join(home, '.claude', 'settings.json'), '{ "mcpServers": ');
    const before = await run(() => runMcpStatus());
    const protect = await run(() => runProtectMcp([]));
    const config = JSON.parse(fs.readFileSync(cursor, 'utf-8'));
    const args: string[] = config.mcpServers.github.args;
    const at = args.indexOf('--binding');
    expect(at).toBeGreaterThan(-1);
    config.mcpServers.github.args = [...args.slice(0, at), ...args.slice(at + 2)];
    write(cursor, config);
    const after = await run(() => runMcpStatus());

    const named = commandsIn([before, protect, after].join('\n'));
    expect(named.length).toBeGreaterThanOrEqual(8);
    expect([...new Set(named.map((n) => n.verb))].sort()).toEqual(['mcp-status', 'mcp-unprotect', 'protect-mcp']);
    for (const { command, verb } of named) {
      expect(command).toBe(`npx secretless-ai@${VERSION} ${verb}`);
      expect(CLI_SOURCE, `${verb} is not dispatched`).toContain(`case '${verb}':`);
    }
  });

  it('a wrapper copy names the version it records in its fix line, and each command is a registered command', () => {
    const named = commandsIn(refusedByInstalledCopy());

    expect(named.map((n) => n.verb)).toEqual(['mcp-status', 'protect-mcp']);
    for (const { command, verb } of named) {
      expect(command).toBe(`npx secretless-ai@${VERSION} ${verb}`);
      expect(CLI_SOURCE, `${verb} is not dispatched`).toContain(`case '${verb}':`);
    }
  });

  it("with the wrapper's version unreadable ('unknown'), the same copy's fix line names the unversioned form", () => {
    const recorded = commandsIn(refusedByInstalledCopy());
    const unread = commandsIn(refusedByInstalledCopy((binDir) => fs.rmSync(path.join(binDir, WRAPPER_VERSION_FILE))));

    expect(recorded.map((n) => n.command)).toEqual([
      `npx secretless-ai@${VERSION} mcp-status`,
      `npx secretless-ai@${VERSION} protect-mcp`,
    ]);
    expect(unread.map((n) => n.command)).toEqual(['npx secretless-ai mcp-status', 'npx secretless-ai protect-mcp']);
  });
});

/** A line run by /bin/sh from `cwd`, as a reader runs a printed command; what it printed. */
function sh(line: string, cwd: string): string {
  const res = spawnSync('/bin/sh', ['-c', line], {
    cwd,
    encoding: 'utf-8',
    // npm stays off the network and away from the real cache.
    env: { ...childEnv(), npm_config_offline: 'true', npm_config_update_notifier: 'false', npm_config_cache: path.join(home, '.npm') },
  });
  return `${res.stdout}${res.stderr}`;
}

/** A command of the built CLI run from `cwd`; what it printed. */
function builtCli(args: string[], cwd: string): string {
  const res = spawnSync(process.execPath, [CLI_PATH, ...args], { cwd, encoding: 'utf-8', env: childEnv() });
  expect(res.status, `${args.join(' ')}: ${res.stderr}`).toBe(0);
  return res.stdout;
}

/** The node binary and CLI script a printed command names, or null when it is not in the path form. */
function pathsOf(command: string, verb: string) {
  return pathFormOf(command.slice(0, -(verb.length + 1)));
}

describe('a printed command runs the build that printed it, from any directory', () => {
  it('T1: each command the wrapper, protect-mcp and mcp-status print, run from two directories below a project root that holds another package of this name and version and bin entries under its names, runs this build', () => {
    const marker = ['planted', 'copy', 'ran'].join(' ');
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-planted-'));
    try {
      write(path.join(root, 'package.json'), { name: 'planted-project', version: '1.0.0', private: true });
      const stub = path.join(root, 'node_modules', 'secretless-ai');
      write(path.join(stub, 'package.json'), { name: 'secretless-ai', version: VERSION, bin: { 'secretless-ai': 'marker.js' } });
      write(path.join(stub, 'marker.js'), `#!/usr/bin/env node\nconsole.log(${JSON.stringify(marker)});\n`);
      fs.chmodSync(path.join(stub, 'marker.js'), 0o755);
      const dotBin = path.join(root, 'node_modules', '.bin');
      fs.mkdirSync(dotBin, { recursive: true });
      for (const name of ['secretless-ai', `secretless-ai@${VERSION}`]) {
        fs.symlinkSync(path.join('..', 'secretless-ai', 'marker.js'), path.join(dotBin, name));
      }
      const deep = path.join(root, 'a', 'b');
      fs.mkdirSync(deep, { recursive: true });

      // mcp-status over an exposed home server, protect-mcp, then the wrapper
      // for the protected entry with its binding taken out.
      const cursor = write(path.join(home, '.cursor', 'mcp.json'), { mcpServers: { github: plain() } });
      const status = builtCli(['mcp-status'], deep);
      const protect = builtCli(['protect-mcp'], deep);
      const args: string[] = JSON.parse(fs.readFileSync(cursor, 'utf-8')).mcpServers.github.args;
      const at = args.indexOf('--binding');
      expect(at).toBeGreaterThan(-1);
      const refused = spawnSync(process.execPath, [WRAPPER_JS, ...args.slice(0, at), ...args.slice(at + 2)], {
        cwd: deep,
        encoding: 'utf-8',
        env: childEnv(),
      });
      expect(refused.status).toBe(1);

      const printed = { 'mcp-status': commandsIn(status), 'protect-mcp': commandsIn(protect), wrapper: commandsIn(refused.stderr) };
      expect(printed['mcp-status'].map((n) => n.verb)).toContain('protect-mcp');
      expect(printed['protect-mcp'].map((n) => n.verb)).toEqual(expect.arrayContaining(['mcp-status', 'mcp-unprotect']));
      expect(printed.wrapper.map((n) => n.verb)).toEqual(['mcp-status', 'protect-mcp']);

      for (const { command, verb } of Object.values(printed).flat()) {
        // The line as printed, then its two words with --version.
        expect(sh(command, deep), command).not.toContain(marker);
        const paths = pathsOf(command, verb);
        expect(paths, `${command} names no node binary and CLI script`).not.toBeNull();
        expect(fs.realpathSync(paths!.node)).toBe(fs.realpathSync(process.execPath));
        expect(fs.realpathSync(paths!.cli)).toBe(fs.realpathSync(CLI_PATH));
        const version = sh(`${command.slice(0, -(verb.length + 1))} --version`, deep);
        expect(version).toContain(`secretless-ai ${VERSION}`);
        expect(version).not.toContain(marker);
      }
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('T4: the built wrapper, started with a stub child, names the cli.js beside it', () => {
    // The store's directory exists, so the wrapper reaches its binding check.
    fs.mkdirSync(path.join(home, '.secretless-ai', 'mcp-vault'), { recursive: true });
    const sentinel = path.join(project, 'started.json');
    const stub = ['-e', `require('fs').writeFileSync(${JSON.stringify(sentinel)}, '')`];

    const res = spawnSync(process.execPath, [WRAPPER_JS, '--server', 'github', '--client', 'cursor', '--', process.execPath, ...stub], {
      cwd: project,
      encoding: 'utf-8',
      env: childEnv(),
    });

    expect(res.status).toBe(1);
    expect(fs.existsSync(sentinel)).toBe(false);
    const named = commandsIn(res.stderr);
    expect(named.map((n) => n.verb)).toEqual(['mcp-status', 'protect-mcp']);
    for (const { command, verb } of named) {
      const paths = pathsOf(command, verb);
      expect(paths, `${command} names no node binary and CLI script`).not.toBeNull();
      expect(fs.realpathSync(paths!.cli)).toBe(fs.realpathSync(path.join(path.dirname(WRAPPER_JS), 'cli.js')));
    }
  });
});
