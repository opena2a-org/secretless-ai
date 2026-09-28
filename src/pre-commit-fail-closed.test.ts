import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { execFileSync, spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { hookCommand, hookScript } from './git-hook';
import { VERSION } from './commands/utils';

/**
 * The pre-commit gate fails closed (#191). Real git, the built CLI
 * (`dist/cli.js`), and the generated hook body run by `sh`:
 *
 *   - an ancestor `node_modules/.bin/secretless-ai` stub used to answer for the
 *     unpinned `npx secretless-ai scan-staged`, and the commit passed;
 *   - a committed `*` in `.secretlessignore` switched the scan off;
 *   - a failed `git diff` returned 0;
 *   - files over 5 MB, unreadable files and lines over 4096 characters were
 *     skipped without a word.
 */

const CLI_PATH = path.resolve(__dirname, '..', 'dist', 'cli.js');
const hasBuild = fs.existsSync(CLI_PATH);
const itIfBuilt = hasBuild ? it : it.skip;
// Assembled at runtime so the source carries no token-shaped literal.
const TOKEN = ['ghp', 'abcdefghijklmnopqrstuvwxyz1234567890'].join('_');

function childEnv(extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env, OPENA2A_TELEMETRY: 'off', ...extra };
  // Run inside a git hook, git exports these; a child git would then act on
  // the outer repository instead of the temp one.
  for (const k of ['GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_PREFIX', 'GIT_COMMON_DIR']) delete env[k];
  return env;
}

function git(cwd: string, ...args: string[]): string {
  return execFileSync('git', args, { cwd, encoding: 'utf-8', env: childEnv(), stdio: ['pipe', 'pipe', 'pipe'] });
}

function initRepo(dir: string): string {
  fs.mkdirSync(dir, { recursive: true });
  git(dir, 'init', '-q');
  return dir;
}

function scanStaged(cwd: string, args: string[] = [], env: NodeJS.ProcessEnv = {}) {
  const res = spawnSync(process.execPath, [CLI_PATH, 'scan-staged', ...args], {
    cwd,
    encoding: 'utf-8',
    env: childEnv(env),
  });
  return { status: res.status, stderr: res.stderr };
}

describe('pre-commit hook body (#191)', () => {
  it('pins the running version, stays on the npm cache, and ignores .secretlessignore', () => {
    expect(hookCommand('9.9.9')).toBe('npm_config_offline=true npx --yes secretless-ai@9.9.9 scan-staged --no-ignore');
    const body = hookScript('9.9.9');
    expect(body).toContain(hookCommand('9.9.9'));
    expect(body).not.toMatch(/^npx secretless-ai scan-staged/m);
    expect(hookScript()).toContain(`secretless-ai@${VERSION} scan-staged`);
  });

  it('refuses a version that is not an exact semver string instead of writing it into the script', () => {
    expect(hookCommand('1.2.3-rc.1')).toContain('secretless-ai@1.2.3-rc.1 scan-staged');
    for (const bad of ['1.0.0; touch pwned #', '$(id)', 'latest', '^1.2.3', '1.2', '']) {
      expect(() => hookCommand(bad)).toThrow(/not an exact semver version/);
      expect(() => hookScript(bad)).toThrow(/not an exact semver version/);
    }
  });
});

describe('pre-commit gate fails closed (#191)', () => {
  let tmp: string;

  beforeEach(() => {
    tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-191-')));
  });

  afterEach(() => {
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  it('an ancestor node_modules/.bin stub does not answer for the hook', () => {
    const marker = path.join(tmp, 'stub-ran');
    const bin = path.join(tmp, 'anc', 'node_modules', '.bin');
    fs.mkdirSync(bin, { recursive: true });
    fs.writeFileSync(path.join(bin, 'secretless-ai'), `#!/bin/sh\ntouch "${marker}"\nexit 0\n`, { mode: 0o755 });
    const repo = initRepo(path.join(tmp, 'anc', 'repo'));
    fs.writeFileSync(path.join(repo, 'server.crt'), 'x\n');
    git(repo, 'add', 'server.crt');
    fs.writeFileSync(path.join(tmp, 'pre-commit'), hookScript(VERSION), { mode: 0o755 });

    // An empty npm cache makes the outcome independent of this machine: the
    // pinned version is not cached, so the hook must refuse, not fall through.
    const env = childEnv({ npm_config_cache: path.join(tmp, 'npm-cache'), npm_config_update_notifier: 'false' });

    // Control: the unpinned line the hook used to run is answered by the stub.
    const unpinned = spawnSync('sh', ['-c', 'npx secretless-ai scan-staged'], { cwd: repo, env, encoding: 'utf-8' });
    expect(unpinned.status).toBe(0);
    expect(fs.existsSync(marker)).toBe(true);
    fs.rmSync(marker);

    const res = spawnSync('sh', [path.join(tmp, 'pre-commit')], { cwd: repo, env, encoding: 'utf-8' });
    expect(fs.existsSync(marker)).toBe(false);
    expect(res.status).not.toBe(0);
    expect(res.stderr).toContain(`secretless-ai@${VERSION} is not in the npm cache`);
    expect(res.stderr).toContain(`npx --yes secretless-ai@${VERSION} --version`);
  }, 60_000);

  itIfBuilt('a committed `*` .secretlessignore does not disable the hook scan', () => {
    const repo = initRepo(path.join(tmp, 'repo'));
    fs.writeFileSync(path.join(repo, '.secretlessignore'), '*\n');
    fs.writeFileSync(path.join(repo, 'server.crt'), 'x\n');
    git(repo, 'add', '.secretlessignore', 'server.crt');

    // Without --no-ignore the ignore file hides the staged certificate ...
    expect(scanStaged(repo).status).toBe(0);
    // ... which is why the hook passes it.
    expect(hookCommand()).toMatch(/scan-staged --no-ignore$/);
    const res = scanStaged(repo, ['--no-ignore']);
    expect(res.status).toBe(1);
    expect(res.stderr).toContain('! server.crt');
  });

  itIfBuilt('a staged set that cannot be listed exits non-zero', () => {
    const notRepo = path.join(tmp, 'plain');
    fs.mkdirSync(notRepo);
    const res = scanStaged(notRepo, [], { GIT_CEILING_DIRECTORIES: tmp });
    expect(res.status).toBe(1);
    expect(res.stderr).toContain('could not list the staged files: not a git repository');
  });

  itIfBuilt('a staged file over 5 MB is reported and blocks unless --allow-unscanned', () => {
    const repo = initRepo(path.join(tmp, 'repo'));
    fs.writeFileSync(path.join(repo, 'big.txt'), 'padding line\n'.repeat(500_000));
    git(repo, 'add', 'big.txt');

    const blocked = scanStaged(repo);
    expect(blocked.status).toBe(1);
    expect(blocked.stderr).toContain('staged files could not be scanned');
    expect(blocked.stderr).toContain('! big.txt (larger than 5 MB)');

    const allowed = scanStaged(repo, ['--allow-unscanned']);
    expect(allowed.status).toBe(0);
    expect(allowed.stderr).toContain('- big.txt (larger than 5 MB)');
  });

  itIfBuilt('a credential on a line over 4096 characters is found', () => {
    const repo = initRepo(path.join(tmp, 'repo'));
    fs.writeFileSync(path.join(repo, 'bundle.min.js'), `var a="${'x'.repeat(6000)}",t="${TOKEN}";\n`);
    git(repo, 'add', 'bundle.min.js');

    const res = scanStaged(repo);
    expect(res.status).toBe(1);
    expect(res.stderr).toContain('GitHub Token in bundle.min.js:1');
  });

  itIfBuilt('a non-ASCII path is matched and scanned, not quoted past the patterns', () => {
    const repo = initRepo(path.join(tmp, 'repo'));
    fs.writeFileSync(path.join(repo, 'café.pem'), 'x\n');
    git(repo, 'add', 'café.pem');

    const res = scanStaged(repo);
    expect(res.status).toBe(1);
    expect(res.stderr).toContain('! café.pem');
  });

  itIfBuilt('a staged submodule pointer neither blocks nor counts as unscanned', () => {
    const repo = initRepo(path.join(tmp, 'repo'));
    git(repo, 'update-index', '--add', '--cacheinfo', `160000,${'1'.repeat(40)},vendor/lib`);
    fs.writeFileSync(path.join(repo, 'app.js'), 'const x = 1;\n');
    git(repo, 'add', 'app.js');

    const res = scanStaged(repo);
    expect(res.stderr).toBe('');
    expect(res.status).toBe(0);
  });
});
