/**
 * The command prefix written into the pre-commit hook, the Claude Code Stop
 * hook and the git credential helper: the running copy's node and CLI paths
 * when they resolve and the copy is not in the npx cache, otherwise
 * `npx --yes secretless-ai@<version>` run offline, and never a bare
 * `npx secretless-ai`. A body that names the copy by path checks that its CLI
 * file is there before it runs it.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { commandPrefixForHooks, resolveHookPrefix } from './hook-prefix';
import { shellHookCommand } from './env';
import { installPreCommitHook, hookScript, isHookInstalled, preCommitTargetMissing } from './git-hook';
import { init, stopHookCommand, stopHookTargetMissing, promptCheckCommand, promptCheckTargetMissing } from './init';
import { helperCommand, helperKey, installHelper, uninstallHelper, readGlobalValues, isOurHelper, type GitRunner } from './git-credential';
import { runGitCredential } from './commands/git-credential';
import { VERSION } from './commands/utils';

/** `npx secretless-ai` with no version after the name. */
const BARE_NPX = /npx secretless-ai(?!@)/;
const PINNED_NPX = `npm_config_offline=true npx --yes secretless-ai@${VERSION}`;
const LEGACY_STOP = 'npx secretless-ai clean --last 2>/dev/null || true';

const hasGit = spawnSync('git', ['--version']).status === 0;
const hasNpx = spawnSync('npx', ['--version'], { encoding: 'utf-8' }).status === 0;
const itIfGit = hasGit ? it : it.skip;
const itIfGitAndNpx = hasGit && hasNpx ? it : it.skip;

const quote = (s: string): string => `'${s.replace(/'/g, `'\\''`)}'`;

/**
 * A directory laid out like an installed copy of this package: package.json
 * named `secretless-ai` and `dist/cli.js`. The CLI records the arguments it was
 * started with in `<root>/real-ran`.
 */
function fakeInstall(root: string, name = 'secretless-ai'): string {
  fs.mkdirSync(path.join(root, 'dist'), { recursive: true });
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name, version: VERSION }));
  const script = path.join(root, 'dist', 'cli.js');
  fs.writeFileSync(script, [
    "const fs = require('fs');",
    "const path = require('path');",
    "fs.writeFileSync(path.join(__dirname, '..', 'real-ran'), process.argv.slice(2).join(' '));",
  ].join('\n'));
  return script;
}

describe('commandPrefixForHooks', () => {
  let tmp: string;
  beforeEach(() => { tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-hook-prefix-')); });
  afterEach(() => fs.rmSync(tmp, { recursive: true, force: true }));

  it('names the running copy by path, in the form the shell hook uses, when the copy resolves', () => {
    const script = fakeInstall(path.join(tmp, 'with space', "it's here"));
    const prefix = commandPrefixForHooks({ script, execPath: process.execPath, pathEnv: '' });
    expect(prefix).toBe(shellHookCommand(process.execPath, '', script).map(quote).join(' '));
    expect(prefix).not.toMatch(BARE_NPX);
    expect(prefix).not.toContain('npx');
  });

  it('runs the resolved copy through a shell with its arguments intact', () => {
    const root = path.join(tmp, 'with space', "it's here");
    const script = fakeInstall(root);
    const prefix = commandPrefixForHooks({ script, execPath: process.execPath, pathEnv: '' });
    const res = spawnSync('/bin/sh', ['-c', `${prefix} scan-staged --flag`], { encoding: 'utf-8' });
    expect(res.status, res.stderr).toBe(0);
    expect(fs.readFileSync(path.join(root, 'real-ran'), 'utf-8')).toBe('scan-staged --flag');
  });

  it('pins the running version and runs offline when the CLI file is missing', () => {
    const prefix = commandPrefixForHooks({ script: path.join(tmp, 'dist', 'cli.js'), execPath: process.execPath });
    expect(prefix).toBe(PINNED_NPX);
    expect(prefix).not.toMatch(BARE_NPX);
  });

  it('pins the running version when the node binary is missing', () => {
    const script = fakeInstall(path.join(tmp, 'pkg'));
    expect(commandPrefixForHooks({ script, execPath: path.join(tmp, 'no-node') })).toBe(PINNED_NPX);
  });

  it('pins the running version when the CLI file belongs to another package', () => {
    const script = fakeInstall(path.join(tmp, 'host'), 'some-host-cli');
    expect(commandPrefixForHooks({ script, execPath: process.execPath })).toBe(PINNED_NPX);
  });

  it('pins the running version when a path holds a control character', () => {
    const script = fakeInstall(path.join(tmp, 'line\nbreak'));
    expect(commandPrefixForHooks({ script, execPath: process.execPath })).toBe(PINNED_NPX);
  });

  it('refuses a version that is not one exact release', () => {
    const missing = path.join(tmp, 'dist', 'cli.js');
    for (const version of ['latest', '^0.23.1', '0.23', '0.23.1 || 1.0.0', '0.23.1;id', '$(id)']) {
      expect(() => commandPrefixForHooks({ script: missing, version }), version).toThrow(/exact/);
    }
    expect(commandPrefixForHooks({ script: missing, version: '1.2.3-rc.1+build.5' }))
      .toBe('npm_config_offline=true npx --yes secretless-ai@1.2.3-rc.1+build.5');
  });

  it('defaults to the copy that is running', () => {
    // Under the test runner this module is the TypeScript source, with no cli.js beside it.
    expect(commandPrefixForHooks()).not.toMatch(BARE_NPX);
    expect(commandPrefixForHooks()).toBe(commandPrefixForHooks({ script: path.join(__dirname, 'cli.js') }));
  });
});

describe('the pre-commit hook runs the pinned prefix', () => {
  let tmp: string;
  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-hook-prefix-git-'));
    fs.mkdirSync(path.join(tmp, '.git'));
  });
  afterEach(() => fs.rmSync(tmp, { recursive: true, force: true }));

  it('writes the prefix before scan-staged, with no bare npx', () => {
    expect(installPreCommitHook(tmp).installed).toBe(true);
    const content = fs.readFileSync(path.join(tmp, '.git', 'hooks', 'pre-commit'), 'utf-8');
    expect(content).toContain(`\n${commandPrefixForHooks()} scan-staged\n`);
    expect(content).not.toMatch(BARE_NPX);
  });

  it('replaces an unpinned hook it wrote earlier', () => {
    const hookPath = path.join(tmp, '.git', 'hooks', 'pre-commit');
    fs.mkdirSync(path.dirname(hookPath));
    fs.writeFileSync(hookPath, '#!/bin/sh\n# secretless-ai pre-commit hook\nnpx secretless-ai scan-staged\n');
    expect(installPreCommitHook(tmp).message).toBe('Pre-commit hook updated.');
    expect(fs.readFileSync(hookPath, 'utf-8')).not.toMatch(BARE_NPX);
  });

  it('offers the pinned line for a hook it did not write', () => {
    const hookPath = path.join(tmp, '.git', 'hooks', 'pre-commit');
    fs.mkdirSync(path.dirname(hookPath));
    fs.writeFileSync(hookPath, '#!/bin/sh\necho mine\n');
    const result = installPreCommitHook(tmp);
    expect(result.installed).toBe(false);
    expect(result.message).toContain(`${commandPrefixForHooks()} scan-staged`);
    expect(result.message).not.toMatch(BARE_NPX);
  });
});

describe('the Claude Code Stop hook runs the pinned prefix', () => {
  let dir: string;
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-hook-prefix-stop-'));
    fs.mkdirSync(path.join(dir, '.claude'));
  });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

  function stopCommands(): string[] {
    const settings = JSON.parse(fs.readFileSync(path.join(dir, '.claude', 'settings.json'), 'utf-8'));
    return (settings.hooks.Stop as any[]).flatMap((h) => h.hooks.map((hh: any) => hh.command));
  }

  it('writes the prefix before clean --last, with no bare npx and no discarded stderr', () => {
    init(dir);
    const [command, ...rest] = stopCommands();
    expect(rest).toEqual([]);
    expect(command.startsWith(`${commandPrefixForHooks()} clean --last `)).toBe(true);
    expect(command).not.toMatch(BARE_NPX);
    expect(command).not.toContain('2>/dev/null');
    expect(command).toMatch(/>&2/);
    expect(command.endsWith('|| true')).toBe(true);
  });

  it('exits 0 and says so on stderr when the cleaner cannot start', () => {
    init(dir);
    const [command] = stopCommands();
    const res = spawnSync('/bin/sh', ['-c', command], {
      encoding: 'utf-8',
      cwd: dir,
      env: {
        ...process.env,
        // Whatever the command runs, it sees only this directory as home, an
        // empty npm cache and no network.
        HOME: dir,
        npm_config_cache: path.join(dir, 'npm-cache'),
        npm_config_offline: 'true',
        npm_config_update_notifier: 'false',
        PATH: hasNpx ? process.env.PATH : '',
      },
    });
    expect(res.status).toBe(0);
    expect(res.stderr).toMatch(/secretless-ai clean --last failed \(exit [1-9][0-9]*\)/);    expect(res.stdout).toBe('');
  });

  it('replaces the unpinned Stop hook an earlier init wrote, and keeps the user\'s own', () => {
    fs.writeFileSync(path.join(dir, '.claude', 'settings.json'), JSON.stringify({
      hooks: {
        Stop: [
          { matcher: '', hooks: [{ type: 'command', command: LEGACY_STOP }] },
          { matcher: '', hooks: [{ type: 'command', command: 'echo done' }] },
        ],
      },
    }));
    const result = init(dir);
    const commands = stopCommands();
    expect(commands).toHaveLength(2);
    expect(commands[0].startsWith(`${commandPrefixForHooks()} clean --last `)).toBe(true);
    expect(commands[1]).toBe('echo done');
    expect(commands.join('\n')).not.toMatch(BARE_NPX);
    expect(result.filesModified).toContain('.claude/settings.json');

    // A second run finds nothing to change in the Stop hooks.
    init(dir);
    expect(stopCommands()).toEqual(commands);
  });
});

describe('the git credential helper runs the pinned prefix', () => {
  let home: string;
  beforeEach(() => { home = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-hook-prefix-cred-')); });
  afterEach(() => fs.rmSync(home, { recursive: true, force: true }));

  const mapping = { host: 'github.com', name: 'GITHUB_TOKEN' };
  const KEY = helperKey('github.com');

  function gitEnv(extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
    const env: NodeJS.ProcessEnv = {
      ...process.env,
      HOME: home,
      GIT_CONFIG_NOSYSTEM: '1',
      GIT_TERMINAL_PROMPT: '0',
      npm_config_cache: path.join(home, 'npm-cache'),
      npm_config_offline: 'true',
      npm_config_update_notifier: 'false',
      ...extra,
    };
    for (const name of ['XDG_CONFIG_HOME', 'GIT_CONFIG_GLOBAL', 'GIT_CONFIG_SYSTEM', 'GIT_CONFIG_COUNT', 'GIT_CONFIG_PARAMETERS', 'GIT_DIR', 'GIT_ASKPASS', 'SSH_ASKPASS']) {
      delete env[name];
    }
    return env;
  }

  function gitIn(cwd: string): GitRunner {
    return (args) => {
      const res = spawnSync('git', args, { encoding: 'utf-8', env: gitEnv(), cwd });
      return { status: res.status ?? 1, stdout: res.stdout ?? '', stderr: res.stderr ?? '' };
    };
  }

  /** A repository whose node_modules/.bin holds a `secretless-ai` that records it ran. */
  function repoWithPlantedBin(): { repo: string; stubMark: string } {
    const repo = path.join(home, 'repo');
    fs.mkdirSync(path.join(repo, 'node_modules', '.bin'), { recursive: true });
    expect(spawnSync('git', ['init', '-q', repo], { env: gitEnv() }).status).toBe(0);
    const stubMark = path.join(home, 'stub-ran');
    const stub = path.join(repo, 'node_modules', '.bin', 'secretless-ai');
    fs.writeFileSync(stub, `#!/bin/sh\necho "$@" > ${quote(stubMark)}\n`, { mode: 0o755 });
    return { repo, stubMark };
  }

  function fill(repo: string): void {
    spawnSync('git', ['credential', 'fill'], {
      cwd: repo,
      env: gitEnv(),
      input: 'protocol=https\nhost=github.com\n\n',
      encoding: 'utf-8',
    });
  }

  itIfGit('install writes the prefix, with no bare npx', async () => {
    const out: string[] = [];
    const log = console.log;
    console.log = (...a: unknown[]) => { out.push(a.join(' ')); };
    try {
      expect(await runGitCredential(['install', '--host', 'github.com', '--name', 'GITHUB_TOKEN'], { git: gitIn(home) })).toBe(0);
    } finally {
      console.log = log;
    }
    const values = readGlobalValues(gitIn(home), KEY);
    expect(values).toEqual(['', helperCommand(commandPrefixForHooks(), mapping)]);
    expect(values.join('\n')).not.toMatch(BARE_NPX);
  });

  itIfGit('the written helper runs the resolved copy, not a node_modules/.bin in the repository', () => {
    const { repo, stubMark } = repoWithPlantedBin();
    const pkg = path.join(home, 'pkg');
    const script = fakeInstall(pkg);
    installHelper(gitIn(home), commandPrefixForHooks({ script, execPath: process.execPath }), mapping);

    fill(repo);
    expect(fs.existsSync(stubMark)).toBe(false);
    expect(fs.readFileSync(path.join(pkg, 'real-ran'), 'utf-8')).toBe('git-credential --host github.com --name GITHUB_TOKEN get');
  });

  itIfGitAndNpx('the pinned npx form does not run a node_modules/.bin in the repository', () => {
    const { repo, stubMark } = repoWithPlantedBin();
    installHelper(gitIn(home), commandPrefixForHooks({ script: path.join(home, 'none', 'cli.js') }), mapping);
    fill(repo);
    expect(fs.existsSync(stubMark)).toBe(false);
  });

  itIfGitAndNpx('positive control: an unpinned npx helper runs the node_modules/.bin in the repository', () => {
    const { repo, stubMark } = repoWithPlantedBin();
    installHelper(gitIn(home), 'npx secretless-ai', mapping);
    fill(repo);
    expect(fs.readFileSync(stubMark, 'utf-8').trim()).toBe('git-credential --host github.com --name GITHUB_TOKEN get');
  });

  itIfGit('uninstall and re-install recognise the pinned entry in both forms', () => {
    const git = gitIn(home);
    const script = fakeInstall(path.join(home, 'with space'));
    const resolved = commandPrefixForHooks({ script, execPath: process.execPath });
    const pinned = commandPrefixForHooks({ script: path.join(home, 'none', 'cli.js') });

    for (const prefix of [resolved, pinned]) {
      const entry = helperCommand(prefix, mapping);
      expect(isOurHelper(entry, 'github.com')).toBe(true);
      expect(isOurHelper(entry, 'gitlab.com')).toBe(false);
    }

    // An entry an older version wrote is replaced, not kept beside the new one.
    installHelper(git, 'npx secretless-ai', mapping);
    installHelper(git, resolved, mapping);
    expect(readGlobalValues(git, KEY)).toEqual(['', helperCommand(resolved, mapping)]);
    installHelper(git, pinned, mapping);
    expect(readGlobalValues(git, KEY)).toEqual(['', helperCommand(pinned, mapping)]);
    expect(uninstallHelper(git, 'github.com').changed).toBe(true);
    expect(readGlobalValues(git, KEY)).toEqual([]);
  });
});

describe('a copy that runs from the npx cache is not named by path', () => {
  let tmp: string;
  beforeEach(() => { tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-hook-prefix-cache-')); });
  afterEach(() => fs.rmSync(tmp, { recursive: true, force: true }));

  it('pins the running version for a copy under an _npx directory, and says that is why', () => {
    const script = fakeInstall(path.join(tmp, '_npx', 'abc', 'node_modules', 'secretless-ai'));
    expect(commandPrefixForHooks({ script, execPath: process.execPath })).toBe(PINNED_NPX);
    expect(resolveHookPrefix({ script, execPath: process.execPath })).toEqual({ prefix: PINNED_NPX, npxCache: true });
  });

  it('pins the running version for a copy reached through a link into an _npx directory', () => {
    const pkg = path.join(tmp, '_npx', 'abc', 'node_modules', 'secretless-ai');
    fakeInstall(pkg);
    fs.symlinkSync(pkg, path.join(tmp, 'linked'));
    const script = path.join(tmp, 'linked', 'dist', 'cli.js');
    expect(resolveHookPrefix({ script, execPath: process.execPath })).toEqual({ prefix: PINNED_NPX, npxCache: true });
  });

  it('names the copy by path when a directory name only contains _npx', () => {
    const script = fakeInstall(path.join(tmp, 'my_npx', 'node_modules', 'secretless-ai'));
    expect(resolveHookPrefix({ script, execPath: process.execPath, pathEnv: '' })).toEqual({
      prefix: shellHookCommand(process.execPath, '', script).map(quote).join(' '),
      npxCache: false,
    });
  });

  it('does not give the npx cache as the reason when the copy does not resolve', () => {
    const script = path.join(tmp, '_npx', 'gone', 'node_modules', 'secretless-ai', 'dist', 'cli.js');
    expect(resolveHookPrefix({ script, execPath: process.execPath })).toEqual({ prefix: PINNED_NPX, npxCache: false });
  });
});

describe('a hook that names its copy by path checks the CLI file is there first', () => {
  let tmp: string;
  beforeEach(() => { tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-hook-target-')); });
  afterEach(() => fs.rmSync(tmp, { recursive: true, force: true }));

  /** A copy whose path needs quoting, and the prefix that names it. */
  function copy(): { root: string; script: string; prefix: string } {
    const root = path.join(tmp, 'with space', "it's here");
    const script = fakeInstall(root);
    return { root, script, prefix: commandPrefixForHooks({ script, execPath: process.execPath, pathEnv: '' }) };
  }

  it('the pre-commit hook runs the copy, and once it is gone blocks the commit with one line', () => {
    const { root, script, prefix } = copy();
    const content = hookScript(prefix);
    expect(content).toContain(`[ -f ${quote(script)} ] || `);
    expect(content).toContain(`${prefix} scan-staged\n`);
    const hook = path.join(tmp, 'pre-commit');
    fs.writeFileSync(hook, content, { mode: 0o755 });

    let res = spawnSync(hook, [], { encoding: 'utf-8' });
    expect(res.status, res.stderr).toBe(0);
    expect(fs.readFileSync(path.join(root, 'real-ran'), 'utf-8')).toBe('scan-staged');

    fs.rmSync(root, { recursive: true });
    res = spawnSync(hook, [], { encoding: 'utf-8' });
    expect(res.status).toBe(1);
    expect(res.stdout).toBe('');
    expect(res.stderr).toBe(`secretless-ai: pre-commit scanner not found at ${script}. Reinstall: npx secretless-ai hook install\n`);
  });

  it('the Stop hook runs the copy, and once it is gone exits 0 with one line', () => {
    const { root, script, prefix } = copy();
    const command = stopHookCommand(prefix);
    expect(command.startsWith(`[ -f ${quote(script)} ] || `)).toBe(true);
    expect(command.endsWith(`${prefix} clean --last || echo "secretless-ai clean --last failed (exit $?)" >&2 || true`)).toBe(true);

    let res = spawnSync('/bin/sh', ['-c', command], { encoding: 'utf-8' });
    expect(res.status, res.stderr).toBe(0);
    expect(fs.readFileSync(path.join(root, 'real-ran'), 'utf-8')).toBe('clean --last');

    fs.rmSync(root, { recursive: true });
    res = spawnSync('/bin/sh', ['-c', command], { encoding: 'utf-8' });
    expect(res.status).toBe(0);
    expect(res.stdout).toBe('');
    expect(res.stderr).toBe(`secretless-ai: transcript cleaner not found at ${script}. Reinstall: npx secretless-ai init\n`);
  });

  it('the prompt check runs the copy, and once it is gone exits 1 with one line', () => {
    const { root, script, prefix } = copy();
    const command = promptCheckCommand(prefix);
    expect(command.startsWith(`[ -f ${quote(script)} ] || `)).toBe(true);
    expect(command.endsWith(`${prefix} hook --check-prompt`)).toBe(true);

    let res = spawnSync('/bin/sh', ['-c', command], { encoding: 'utf-8' });
    expect(res.status, res.stderr).toBe(0);
    expect(fs.readFileSync(path.join(root, 'real-ran'), 'utf-8')).toBe('hook --check-prompt');

    fs.rmSync(root, { recursive: true });
    res = spawnSync('/bin/sh', ['-c', command], { encoding: 'utf-8' });
    expect(res.status).toBe(1);
    expect(res.stdout).toBe('');
    expect(res.stderr).toBe(`secretless-ai: prompt check not found at ${script}. Reinstall: npx secretless-ai init\n`);
  });

  it('the credential helper runs the copy, and once it is gone exits 1 with one line', () => {
    const { root, script, prefix } = copy();
    const entry = helperCommand(prefix, { host: 'github.com', name: 'GITHUB_TOKEN', username: 'octo' });
    // Git runs an entry that starts with `!` as a shell command, the action appended.
    const run = () => spawnSync('/bin/sh', ['-c', `${entry.slice(1)} get`], { encoding: 'utf-8', input: '' });

    let res = run();
    expect(res.status, res.stderr).toBe(0);
    expect(fs.readFileSync(path.join(root, 'real-ran'), 'utf-8'))
      .toBe('git-credential --host github.com --name GITHUB_TOKEN --username octo get');

    fs.rmSync(root, { recursive: true });
    res = run();
    expect(res.status).toBe(1);
    expect(res.stdout).toBe('');
    expect(res.stderr).toBe(`secretless-ai: credential helper not found at ${script}. Reinstall: npx secretless-ai git-credential install --host github.com --name GITHUB_TOKEN --username octo\n`);
  });

  it('the npx form carries no file test', () => {
    expect(hookScript(PINNED_NPX)).not.toContain('[ -f');
    expect(hookScript(PINNED_NPX)).toContain(`\n${PINNED_NPX} scan-staged\n`);
    expect(stopHookCommand(PINNED_NPX))
      .toBe(`${PINNED_NPX} clean --last || echo "secretless-ai clean --last failed (exit $?)" >&2 || true`);
    expect(helperCommand(PINNED_NPX, { host: 'github.com', name: 'GITHUB_TOKEN' }))
      .toBe(`!${PINNED_NPX} git-credential --host github.com --name GITHUB_TOKEN`);
  });

  it('the prompt check in the npx form carries no file test', () => {
    expect(promptCheckCommand(PINNED_NPX)).toBe(`${PINNED_NPX} hook --check-prompt`);
  });

  it('hook install, init and git-credential still recognise the checked bodies as their own', () => {
    const { prefix } = copy();

    const repo = path.join(tmp, 'repo');
    const hookPath = path.join(repo, '.git', 'hooks', 'pre-commit');
    fs.mkdirSync(path.dirname(hookPath), { recursive: true });
    fs.writeFileSync(hookPath, hookScript(prefix), { mode: 0o755 });
    expect(isHookInstalled(repo)).toBe(true);
    expect(installPreCommitHook(repo).message).toBe('Pre-commit hook updated.');

    const entry = helperCommand(prefix, { host: 'github.com', name: 'GITHUB_TOKEN' });
    expect(isOurHelper(entry, 'github.com')).toBe(true);
    expect(isOurHelper(entry, 'gitlab.com')).toBe(false);

    // A re-run of init replaces the checked Stop hook an earlier run wrote,
    // rather than adding a second one beside it, and keeps the user's own.
    const project = path.join(tmp, 'project');
    fs.mkdirSync(path.join(project, '.claude'), { recursive: true });
    fs.writeFileSync(path.join(project, '.claude', 'settings.json'), JSON.stringify({
      hooks: {
        Stop: [
          { matcher: '', hooks: [{ type: 'command', command: stopHookCommand(prefix) }] },
          { matcher: '', hooks: [{ type: 'command', command: 'echo done' }] },
        ],
      },
    }));
    init(project);
    const settings = JSON.parse(fs.readFileSync(path.join(project, '.claude', 'settings.json'), 'utf-8'));
    const commands = (settings.hooks.Stop as any[]).flatMap((h) => h.hooks.map((hh: any) => hh.command));
    expect(commands).toEqual([stopHookCommand(), 'echo done']);
  });

  it("init replaces the checked prompt check an earlier run wrote, and keeps the user's own", () => {
    const { prefix } = copy();
    const project = path.join(tmp, 'project-prompt');
    fs.mkdirSync(path.join(project, '.claude'), { recursive: true });
    fs.writeFileSync(path.join(project, '.claude', 'settings.json'), JSON.stringify({
      hooks: {
        UserPromptSubmit: [
          { matcher: '', hooks: [{ type: 'command', command: promptCheckCommand(prefix) }] },
          { matcher: '', hooks: [{ type: 'command', command: '/usr/local/bin/my-own-prompt-hook' }] },
        ],
      },
    }));
    init(project);
    const settings = JSON.parse(fs.readFileSync(path.join(project, '.claude', 'settings.json'), 'utf-8'));
    const commands = (settings.hooks.UserPromptSubmit as any[]).flatMap((h) => h.hooks.map((hh: any) => hh.command));
    expect(commands).toEqual([promptCheckCommand(), '/usr/local/bin/my-own-prompt-hook']);
  });
});

describe('the file a hook body names and is missing', () => {
  let tmp: string;
  beforeEach(() => { tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-hook-missing-')); });
  afterEach(() => fs.rmSync(tmp, { recursive: true, force: true }));

  const TAIL = ' clean --last || echo "secretless-ai clean --last failed (exit $?)" >&2 || true';

  function repoWithHook(content: string): string {
    const repo = path.join(tmp, 'repo');
    fs.mkdirSync(path.join(repo, '.git', 'hooks'), { recursive: true });
    fs.writeFileSync(path.join(repo, '.git', 'hooks', 'pre-commit'), content, { mode: 0o755 });
    return repo;
  }

  it('is null while the copy is there, and the CLI file once it is gone, for the checked and the earlier body', () => {
    const root = path.join(tmp, 'with space', "it's here");
    const script = fakeInstall(root);
    const prefix = commandPrefixForHooks({ script, execPath: process.execPath, pathEnv: '' });
    // What 0.23.1 wrote: the prefix and the subcommand, with no file test.
    const earlierHook = `#!/bin/sh\n# secretless-ai pre-commit hook\n\n${prefix} scan-staged\n`;
    const earlierStop = `${prefix}${TAIL}`;

    for (const content of [hookScript(prefix), earlierHook]) {
      expect(preCommitTargetMissing(repoWithHook(content))).toBeNull();
    }
    for (const command of [stopHookCommand(prefix), earlierStop]) {
      expect(stopHookTargetMissing(command)).toBeNull();
    }

    fs.rmSync(root, { recursive: true });
    for (const content of [hookScript(prefix), earlierHook]) {
      expect(preCommitTargetMissing(repoWithHook(content))).toBe(script);
    }
    for (const command of [stopHookCommand(prefix), earlierStop]) {
      expect(stopHookTargetMissing(command)).toBe(script);
    }
  });

  it('names a node binary that is gone', () => {
    const script = fakeInstall(path.join(tmp, 'pkg'));
    const node = path.join(tmp, 'old-node', 'bin', 'node');
    const prefix = `${quote(node)} ${quote(script)}`;
    expect(preCommitTargetMissing(repoWithHook(hookScript(prefix)))).toBe(node);
    expect(stopHookTargetMissing(stopHookCommand(prefix))).toBe(node);
  });

  it('is null for the npx form, a hook this tool did not write, and no hook at all', () => {
    expect(preCommitTargetMissing(repoWithHook(hookScript(PINNED_NPX)))).toBeNull();
    expect(stopHookTargetMissing(stopHookCommand(PINNED_NPX))).toBeNull();
    expect(stopHookTargetMissing(LEGACY_STOP)).toBeNull();
    const gone = `${quote(path.join(tmp, 'node'))} ${quote(path.join(tmp, 'cli.js'))}`;
    expect(preCommitTargetMissing(repoWithHook(`#!/bin/sh\n${gone} scan-staged\n`))).toBeNull();
    expect(stopHookTargetMissing(`${gone} clean --last`)).toBeNull();
    expect(preCommitTargetMissing(path.join(tmp, 'no-repo'))).toBeNull();
  });

  it('reads the prompt check the same way: null while the copy is there, its file once it is gone', () => {
    const root = path.join(tmp, 'prompt', "it's here");
    const script = fakeInstall(root);
    const prefix = commandPrefixForHooks({ script, execPath: process.execPath, pathEnv: '' });
    // The checked body, and one made of the prefix and the subcommand alone.
    const bodies = [promptCheckCommand(prefix), `${prefix} hook --check-prompt`];
    for (const command of bodies) expect(promptCheckTargetMissing(command)).toBeNull();

    fs.rmSync(root, { recursive: true });
    for (const command of bodies) expect(promptCheckTargetMissing(command)).toBe(script);

    const node = path.join(tmp, 'old-node', 'bin', 'node');
    const pkg = fakeInstall(path.join(tmp, 'prompt-pkg'));
    expect(promptCheckTargetMissing(promptCheckCommand(`${quote(node)} ${quote(pkg)}`))).toBe(node);
    expect(promptCheckTargetMissing(promptCheckCommand(PINNED_NPX))).toBeNull();
    expect(promptCheckTargetMissing(stopHookCommand(prefix))).toBeNull();
  });
});
