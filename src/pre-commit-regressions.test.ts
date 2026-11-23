/**
 * Regression tests for the pre-commit hook (#191), each run in a real
 * repository with the hook `hookScript` writes:
 *
 * - a `secretless-ai` stub in an ancestor directory's `node_modules/.bin` does
 *   not run in place of the copy the hook names;
 * - a `.secretlessignore` holding `*` does not turn the hook off;
 * - when `git diff --cached` fails, the hook exits non-zero, rather than
 *   reading the failure as a clean index.
 *
 * Spawns the built entry point (`dist/cli.js`); the failed-diff case runs the
 * hook itself, since `git commit` stops at a corrupt index before any hook.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { hookScript } from './git-hook';
import { commandPrefixForHooks } from './hook-prefix';

const CLI_PATH = path.resolve(__dirname, '..', 'dist', 'cli.js');

const hasGit = spawnSync('git', ['--version']).status === 0;
const hasNpx = spawnSync('npx', ['--version'], { encoding: 'utf-8' }).status === 0;
const itIfGit = hasGit ? it : it.skip;
const itIfGitAndNpx = hasGit && hasNpx ? it : it.skip;

const quote = (s: string): string => `'${s.replace(/'/g, `'\\''`)}'`;

// Assembled so no credential shape is spelled out in this file.
const PAT = ['gh', 'p_', 'R1T2Y3U4I5O6P7A8S9D0F1G2H3J4K5L6Z7X8'].join('');

describe('pre-commit hook regressions (#191)', () => {
  let tmp: string;
  beforeEach(() => { tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-pre-commit-'))); });
  afterEach(() => fs.rmSync(tmp, { recursive: true, force: true }));

  function gitEnv(): NodeJS.ProcessEnv {
    const env: NodeJS.ProcessEnv = {
      ...process.env,
      HOME: tmp,
      GIT_CONFIG_NOSYSTEM: '1',
      GIT_TERMINAL_PROMPT: '0',
      GIT_CEILING_DIRECTORIES: tmp,
      GIT_AUTHOR_NAME: 'Test',
      GIT_AUTHOR_EMAIL: 'test@example.invalid',
      GIT_COMMITTER_NAME: 'Test',
      GIT_COMMITTER_EMAIL: 'test@example.invalid',
      npm_config_cache: path.join(tmp, 'npm-cache'),
      npm_config_offline: 'true',
      npm_config_update_notifier: 'false',
    };
    for (const name of ['XDG_CONFIG_HOME', 'GIT_CONFIG_GLOBAL', 'GIT_CONFIG_SYSTEM', 'GIT_CONFIG_COUNT',
      'GIT_CONFIG_PARAMETERS', 'GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'SECRETLESS_CLI_PREFIX']) {
      delete env[name];
    }
    return env;
  }

  function git(cwd: string, ...args: string[]) {
    return spawnSync('git', args, { cwd, env: gitEnv(), encoding: 'utf-8' });
  }

  /** The prefix the hook writes for the built copy, which names it by path. */
  function builtPrefix(): string {
    const prefix = commandPrefixForHooks({ script: CLI_PATH, execPath: process.execPath });
    expect(prefix).toContain(quote(CLI_PATH));
    return prefix;
  }

  /** A repository at `dir` with `prefix`'s pre-commit hook installed. */
  function repoWithHook(dir: string, prefix: string): string {
    fs.mkdirSync(dir, { recursive: true });
    expect(git(dir, 'init', '-q').status).toBe(0);
    const hooks = path.join(dir, '.git', 'hooks');
    fs.mkdirSync(hooks, { recursive: true });
    fs.writeFileSync(path.join(hooks, 'pre-commit'), hookScript(prefix), { mode: 0o755 });
    return dir;
  }

  function stage(repo: string, files: Record<string, string>): void {
    for (const [name, content] of Object.entries(files)) {
      fs.mkdirSync(path.dirname(path.join(repo, name)), { recursive: true });
      fs.writeFileSync(path.join(repo, name), content);
    }
    expect(git(repo, 'add', '-A').status).toBe(0);
  }

  function commit(repo: string, files: Record<string, string>) {
    stage(repo, files);
    return git(repo, 'commit', '-q', '-m', 'test');
  }

  /** A directory holding a repository, with a `secretless-ai` stub in its `node_modules/.bin` that records it ran. */
  function ancestorWithStub(): { outer: string; stubMark: string } {
    const outer = path.join(tmp, 'outer');
    fs.mkdirSync(path.join(outer, 'node_modules', '.bin'), { recursive: true });
    const stubMark = path.join(tmp, 'stub-ran');
    fs.writeFileSync(path.join(outer, 'node_modules', '.bin', 'secretless-ai'),
      `#!/bin/sh\necho "$@" > ${quote(stubMark)}\nexit 0\n`, { mode: 0o755 });
    return { outer, stubMark };
  }

  itIfGit('a stub in an ancestor node_modules/.bin does not run in place of the copy the hook names', () => {
    const { outer, stubMark } = ancestorWithStub();
    const repo = repoWithHook(path.join(outer, 'repo'), builtPrefix());

    const res = commit(repo, { 'config.js': `const token = "${PAT}";\n` });
    expect(fs.existsSync(stubMark)).toBe(false);
    // The copy the hook names ran, and refused the commit.
    expect(res.status).not.toBe(0);
    expect(res.stderr).toContain('GitHub Token in config.js:1');
  });

  itIfGitAndNpx('a stub in an ancestor node_modules/.bin does not run from the npx form the hook writes', () => {
    const { outer, stubMark } = ancestorWithStub();
    // No copy at this path, so the prefix is the pinned, offline npx form.
    const prefix = commandPrefixForHooks({ script: path.join(tmp, 'missing', 'cli.js') });
    expect(prefix).toMatch(/^npm_config_offline=true npx --yes secretless-ai@\d/);
    const repo = repoWithHook(path.join(outer, 'repo'), prefix);
    commit(repo, { 'a.txt': 'hello\n' });
    expect(fs.existsSync(stubMark)).toBe(false);
  });

  itIfGitAndNpx('positive control: a bare npx hook runs the ancestor stub', () => {
    const { outer, stubMark } = ancestorWithStub();
    const repo = repoWithHook(path.join(outer, 'repo'), 'npx secretless-ai');
    commit(repo, { 'a.txt': 'hello\n' });
    expect(fs.readFileSync(stubMark, 'utf-8')).toMatch(/^scan-staged\b/);
  });

  itIfGit('a .secretlessignore holding * does not turn the hook off', () => {
    const repo = repoWithHook(path.join(tmp, 'repo'), builtPrefix());

    const res = commit(repo, {
      '.secretlessignore': '*\n',
      '.env': 'API_KEY=1\n',
      'config.js': `const token = "${PAT}";\n`,
    });
    expect(res.status).not.toBe(0);
    expect(res.stderr).toContain('Blocked commit');
    expect(res.stderr).toContain('! .env');
    expect(res.stderr).toContain('GitHub Token in config.js:1');
    expect(git(repo, 'rev-parse', '--verify', '-q', 'HEAD').status).not.toBe(0);
  });

  itIfGit('scan-staged sets aside a * ignore file and says so, and still reads one of particular paths', () => {
    const repo = repoWithHook(path.join(tmp, 'repo'), builtPrefix());
    const scanStaged = () => spawnSync(process.execPath, [CLI_PATH, 'scan-staged'], { cwd: repo, env: gitEnv(), encoding: 'utf-8' });

    stage(repo, { '.secretlessignore': '*\n', 'fixtures/config.js': `const token = "${PAT}";\n` });
    let res = scanStaged();
    expect(res.status).toBe(1);
    expect(res.stderr).toContain('.secretlessignore excludes every path');
    expect(res.stderr).toContain('GitHub Token in fixtures/config.js:1');

    stage(repo, { '.secretlessignore': 'fixtures/\n' });
    res = scanStaged();
    expect(res.status, res.stderr).toBe(0);
    expect(res.stderr).not.toContain('excludes every path');
  });

  itIfGit('a failed git diff makes the hook exit non-zero', () => {
    const repo = repoWithHook(path.join(tmp, 'repo'), builtPrefix());
    expect(commit(repo, { 'a.txt': 'hello\n' }).status).toBe(0);

    // A corrupt index: `git diff --cached` inside the repository fails.
    fs.writeFileSync(path.join(repo, '.git', 'index'), 'not an index');
    expect(git(repo, 'diff', '--cached', '--name-only').status).not.toBe(0);

    const hook = spawnSync(path.join(repo, '.git', 'hooks', 'pre-commit'), [], { cwd: repo, env: gitEnv(), encoding: 'utf-8' });
    expect(hook.status).not.toBeNull();
    expect(hook.status).not.toBe(0);
  });
});
