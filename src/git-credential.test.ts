/**
 * The git credential helper backed by the secret store (#238): the protocol,
 * the global git config entries `install` and `uninstall` manage, and git
 * itself reading a stored token through the helper.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { spawn, spawnSync } from 'child_process';
import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import type { AddressInfo } from 'net';
import {
  parseCredentialRequest,
  matchRequest,
  valueProblem,
  formatAnswer,
  hostProblem,
  helperCommand,
  isOurHelper,
  installHelper,
  uninstallHelper,
  readGlobalValues,
  helperKey,
  DEFAULT_GIT_USERNAME,
  type GitRunner,
} from './git-credential';
import { runGitCredential, type GitCredentialDeps } from './commands/git-credential';

const TOKEN = 'ghp_FAKEhelperTokenValue0123456789abcdefAB';
const CLI_PATH = path.resolve(__dirname, '..', 'dist', 'cli.js');
const hasGit = spawnSync('git', ['--version']).status === 0;
const itIfGit = hasGit ? it : it.skip;

/** Environment for a git that reads only `home`'s global config. */
function gitEnv(home: string, extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env, HOME: home, GIT_CONFIG_NOSYSTEM: '1', ...extra };
  for (const name of ['XDG_CONFIG_HOME', 'GIT_CONFIG_GLOBAL', 'GIT_CONFIG_SYSTEM', 'GIT_CONFIG_COUNT', 'GIT_CONFIG_PARAMETERS', 'GIT_DIR', 'GIT_ASKPASS', 'SSH_ASKPASS']) {
    delete env[name];
  }
  return env;
}

function gitIn(home: string): GitRunner {
  return (args) => {
    const res = spawnSync('git', args, { encoding: 'utf-8', env: gitEnv(home), cwd: home });
    return { status: res.status ?? 1, stdout: res.stdout ?? '', stderr: res.stderr ?? '' };
  };
}

describe('the git credential protocol', () => {
  it('reads attributes up to the blank line, CRLF or not', () => {
    const req = parseCredentialRequest('protocol=https\r\nhost=github.com\r\n\r\nhost=evil.example\n');
    expect(req.get('protocol')).toBe('https');
    expect(req.get('host')).toBe('github.com');
  });

  it('skips array attributes and treats __proto__ as an ordinary attribute', () => {
    const req = parseCredentialRequest('capability[]=authtype\n__proto__=x\nprotocol=https\nhost=github.com\n');
    expect(req.has('capability[]')).toBe(false);
    expect(req.get('__proto__')).toBe('x');
    expect(({} as Record<string, unknown>).x).toBeUndefined();
  });

  it('expands url= into protocol, host and username, the way git does', () => {
    const req = parseCredentialRequest('url=https://octo@git.example.com:8443/org/repo.git\n');
    expect(req.get('protocol')).toBe('https');
    expect(req.get('host')).toBe('git.example.com:8443');
    expect(req.get('username')).toBe('octo');
  });

  it('answers only https requests for its own host, any case', () => {
    const mapping = { host: 'github.com', name: 'GITHUB_TOKEN' };
    expect(matchRequest(parseCredentialRequest('protocol=https\nhost=GitHub.com\n'), mapping))
      .toEqual({ ours: true, username: DEFAULT_GIT_USERNAME });
    expect(matchRequest(parseCredentialRequest('protocol=http\nhost=github.com\n'), mapping).ours).toBe(false);
    expect(matchRequest(parseCredentialRequest('host=github.com\n'), mapping).ours).toBe(false);
    expect(matchRequest(parseCredentialRequest('protocol=https\nhost=gitlab.com\n'), mapping).ours).toBe(false);
    expect(matchRequest(parseCredentialRequest('protocol=https\nhost=github.com:8443\n'), mapping).ours).toBe(false);
  });

  it('keeps the requested user, and never answers for a different user than --username', () => {
    const asked = parseCredentialRequest('protocol=https\nhost=github.com\nusername=octo\n');
    expect(matchRequest(asked, { host: 'github.com', name: 'T' })).toEqual({ ours: true, username: 'octo' });
    expect(matchRequest(asked, { host: 'github.com', name: 'T', username: 'octo' })).toEqual({ ours: true, username: 'octo' });
    expect(matchRequest(asked, { host: 'github.com', name: 'T', username: 'someone-else' }).ours).toBe(false);
    const anonymous = parseCredentialRequest('protocol=https\nhost=github.com\n');
    expect(matchRequest(anonymous, { host: 'github.com', name: 'T', username: 'bot' })).toEqual({ ours: true, username: 'bot' });
  });

  it('refuses a value the protocol cannot carry instead of trimming it', () => {
    expect(valueProblem(TOKEN)).toBeNull();
    expect(valueProblem('')).toMatch(/empty/);
    expect(valueProblem(`${TOKEN}\n`)).toMatch(/line break/);
    expect(valueProblem(`${TOKEN}\r`)).toMatch(/line break/);
    expect(valueProblem(`a\0b`)).toMatch(/NUL/);
    expect(formatAnswer('x-access-token', TOKEN)).toBe(`username=x-access-token\npassword=${TOKEN}\n`);
  });

  it('takes a host name only, never a URL or a shell word', () => {
    expect(hostProblem('github.com')).toBeNull();
    expect(hostProblem('git.example.com:8443')).toBeNull();
    expect(hostProblem('https://github.com/org')).toMatch(/--host github\.com/);
    expect(hostProblem('github.com;touch x')).not.toBeNull();
    expect(hostProblem('-c')).not.toBeNull();
  });

  it('recognises its own entry for a host under any command prefix, and nothing else', () => {
    const ours = helperCommand('npx secretless-ai', { host: 'github.com', name: 'GITHUB_TOKEN', username: 'octo' });
    expect(ours).toBe('!npx secretless-ai git-credential --host github.com --name GITHUB_TOKEN --username octo');
    expect(isOurHelper(ours, 'github.com')).toBe(true);
    expect(isOurHelper(ours, 'gitlab.com')).toBe(false);
    expect(isOurHelper('!opena2a secrets git-credential --host github.com --name T', 'github.com')).toBe(true);
    expect(isOurHelper('!/opt/homebrew/bin/gh auth git-credential', 'github.com')).toBe(false);
    expect(isOurHelper('store', 'github.com')).toBe(false);
    expect(isOurHelper('', 'github.com')).toBe(false);
  });
});

describe('install and uninstall manage only their own global git config entries', () => {
  let home: string;
  beforeEach(() => { home = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-gitcred-cfg-')); });
  afterEach(() => fs.rmSync(home, { recursive: true, force: true }));

  const KEY = helperKey('github.com');
  const mapping = { host: 'github.com', name: 'GITHUB_TOKEN' };
  const ours = helperCommand('npx secretless-ai', mapping);

  itIfGit('install writes an empty entry and the helper, and no value', () => {
    const git = gitIn(home);
    const change = installHelper(git, 'npx secretless-ai', mapping);
    expect(change.changed).toBe(true);
    expect(readGlobalValues(git, KEY)).toEqual(['', ours]);
    const text = fs.readFileSync(path.join(home, '.gitconfig'), 'utf-8');
    expect(text).not.toContain('password');
    expect(fs.existsSync(path.join(home, '.git-credentials'))).toBe(false);
    expect(installHelper(git, 'npx secretless-ai', mapping).changed).toBe(false);
    expect(readGlobalValues(git, KEY)).toEqual(['', ours]);
  });

  itIfGit('uninstall restores exactly what was there before install', () => {
    const git = gitIn(home);
    git(['config', '--global', 'credential.helper', 'store']);
    git(['config', '--global', '--add', KEY, '']);
    git(['config', '--global', '--add', KEY, '!gh auth git-credential']);
    const before = readGlobalValues(git, KEY);

    installHelper(git, 'npx secretless-ai', mapping);
    expect(readGlobalValues(git, KEY)).toEqual(['', '!gh auth git-credential', '', ours]);

    const change = uninstallHelper(git, 'github.com');
    expect(change.changed).toBe(true);
    expect(readGlobalValues(git, KEY)).toEqual(before);
    expect(readGlobalValues(git, 'credential.helper')).toEqual(['store']);
    expect(uninstallHelper(git, 'github.com').changed).toBe(false);
  });

  itIfGit("keeps the user's own empty entry and moves the host when re-run with another name", () => {
    const git = gitIn(home);
    git(['config', '--global', '--add', KEY, '']);
    installHelper(git, 'npx secretless-ai', mapping);
    const moved = { host: 'github.com', name: 'GH_BOT_TOKEN', username: 'bot' };
    installHelper(git, 'npx secretless-ai', moved);
    expect(readGlobalValues(git, KEY)).toEqual(['', '', helperCommand('npx secretless-ai', moved)]);
    uninstallHelper(git, 'github.com');
    expect(readGlobalValues(git, KEY)).toEqual(['']);
  });

  itIfGit('leaves another host alone', () => {
    const git = gitIn(home);
    installHelper(git, 'npx secretless-ai', mapping);
    installHelper(git, 'npx secretless-ai', { host: 'gitlab.com', name: 'GITLAB_TOKEN' });
    uninstallHelper(git, 'github.com');
    expect(readGlobalValues(git, KEY)).toEqual([]);
    expect(readGlobalValues(git, helperKey('gitlab.com'))).toHaveLength(2);
  });
});

describe('git-credential command', () => {
  let out: string[];
  let err: string[];
  let answers: string[];
  let storeOpened: number;

  beforeEach(() => {
    out = [];
    err = [];
    answers = [];
    storeOpened = 0;
    vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { out.push(a.join(' ')); });
    vi.spyOn(console, 'error').mockImplementation((...a: unknown[]) => { err.push(a.join(' ')); });
  });
  afterEach(() => vi.restoreAllMocks());

  function deps(input: string, stored: Record<string, string>, tty: { stdin?: boolean; stdout?: boolean } = {}): GitCredentialDeps {
    return {
      createStore: () => {
        storeOpened++;
        return { getSecret: async (name: string) => stored[name] };
      },
      readInput: async () => input,
      writeAnswer: (t) => { answers.push(t); },
      stdinIsTTY: tty.stdin ?? false,
      stdoutIsTTY: tty.stdout ?? false,
      git: () => { throw new Error('git must not run for this action'); },
    };
  }

  const GET = ['--host', 'github.com', '--name', 'GITHUB_TOKEN', 'get'];
  const REQUEST = 'protocol=https\nhost=github.com\n\n';

  it('get answers git with the stored token', async () => {
    const code = await runGitCredential(GET, deps(REQUEST, { GITHUB_TOKEN: TOKEN }));
    expect(code).toBe(0);
    expect(answers).toEqual([`username=x-access-token\npassword=${TOKEN}\n`]);
    expect(out.join('\n') + err.join('\n')).not.toContain(TOKEN);
  });

  it('get in a terminal exits non-zero, prints no value and never opens the store', async () => {
    for (const tty of [{ stdout: true }, { stdin: true }]) {
      answers = [];
      const code = await runGitCredential(GET, deps(REQUEST, { GITHUB_TOKEN: TOKEN }, tty));
      expect(code).toBe(1);
      expect(answers).toEqual([]);
      expect(storeOpened).toBe(0);
      expect(err.join('\n')).toMatch(/does not print a value to a terminal/);
      expect(out.join('\n') + err.join('\n')).not.toContain(TOKEN);
    }
  });

  it('get answers nothing for plain http or another host, without opening the store', async () => {
    for (const input of ['protocol=http\nhost=github.com\n', 'protocol=https\nhost=gitlab.com\n']) {
      expect(await runGitCredential(GET, deps(input, { GITHUB_TOKEN: TOKEN }))).toBe(0);
    }
    expect(answers).toEqual([]);
    expect(storeOpened).toBe(0);
  });

  it('get names the command to store a missing secret', async () => {
    expect(await runGitCredential(GET, deps(REQUEST, {}))).toBe(1);
    expect(answers).toEqual([]);
    expect(err.join('\n')).toMatch(/GITHUB_TOKEN is not in the secret store/);
    expect(err.join('\n')).toMatch(/secret set GITHUB_TOKEN/);
  });

  it('get refuses a stored value with a line break and does not print it', async () => {
    expect(await runGitCredential(GET, deps(REQUEST, { GITHUB_TOKEN: `${TOKEN}\nhost=evil.example` }))).toBe(1);
    expect(answers).toEqual([]);
    expect(err.join('\n')).toMatch(/line break/);
    expect(err.join('\n')).not.toContain(TOKEN);
  });

  it('store and erase write nothing and never open the store', async () => {
    const withPassword = `${REQUEST.trim()}\nusername=x-access-token\npassword=${TOKEN}\n\n`;
    expect(await runGitCredential(['--host', 'github.com', '--name', 'GITHUB_TOKEN', 'store'], deps(withPassword, {}))).toBe(0);
    expect(await runGitCredential(['--host', 'github.com', '--name', 'GITHUB_TOKEN', 'erase'], deps(withPassword, {}))).toBe(0);
    expect(answers).toEqual([]);
    expect(storeOpened).toBe(0);
    expect(err.join('\n')).toMatch(/did not accept the token stored as GITHUB_TOKEN/);
    expect(out.join('\n') + err.join('\n')).not.toContain(TOKEN);
  });

  it('install and uninstall refuse a URL, a missing name, and a flag that does not apply', async () => {
    const d = deps('', {});
    expect(await runGitCredential(['install', '--host', 'https://github.com', '--name', 'T'], d)).toBe(2);
    expect(err.join('\n')).toMatch(/--host github\.com/);
    expect(await runGitCredential(['install', '--host', 'github.com'], d)).toBe(2);
    expect(await runGitCredential(['uninstall', '--host', 'github.com', '--name', 'T'], d)).toBe(2);
    expect(await runGitCredential(['instal', '--host', 'github.com', '--name', 'T'], d)).toBe(2);
    expect(err.join('\n')).toMatch(/did you mean `install`/);
    expect(await runGitCredential([], d)).toBe(2);
  });
});

/**
 * Git itself, asking the helper `install` configured, with the token served by
 * a local Vault stub: no OS keychain is reached, and the value is what git gets.
 */
describe('git reads the stored token through the installed helper', () => {
  const hasBuild = fs.existsSync(CLI_PATH);
  const itE2e = hasBuild && hasGit ? it : it.skip;

  let home: string;
  let server: http.Server;
  let vaultAddr: string;

  beforeEach(async () => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-gitcred-e2e-'));
    fs.mkdirSync(path.join(home, '.secretless-ai'));
    fs.writeFileSync(path.join(home, '.secretless-ai', 'config.json'), JSON.stringify({ backend: 'vault', cacheTtl: 0 }) + '\n');
    server = http.createServer((req, res) => {
      req.resume();
      res.setHeader('Content-Type', 'application/json');
      if (req.method === 'GET' && req.url === '/v1/secret/data/secret/GITHUB_TOKEN') {
        res.end(JSON.stringify({ data: { data: { value: TOKEN } } }));
        return;
      }
      res.statusCode = 404;
      res.end('{"errors":[]}');
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
    vaultAddr = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  afterEach(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    fs.rmSync(home, { recursive: true, force: true });
  });

  function env(): NodeJS.ProcessEnv {
    const quote = (s: string): string => `'${s.replace(/'/g, `'\\''`)}'`;
    return gitEnv(home, {
      GIT_TERMINAL_PROMPT: '0',
      OPENA2A_TELEMETRY: 'off',
      VAULT_ADDR: vaultAddr,
      VAULT_TOKEN: 'stub-vault-token-for-a-test-store',
      // The helper entry `install` writes runs this build, not a registry copy.
      SECRETLESS_CLI_PREFIX: `${quote(process.execPath)} ${quote(CLI_PATH)}`,
    });
  }

  /** Async: the Vault stub answers on this process's event loop. */
  function run(cmd: string, args: string[], input = ''): Promise<{ status: number | null; stdout: string; stderr: string }> {
    return new Promise((resolve) => {
      const child = spawn(cmd, args, { env: env(), cwd: home, stdio: ['pipe', 'pipe', 'pipe'] });
      let stdout = '';
      let stderr = '';
      child.stdout.on('data', (d: Buffer) => { stdout += d.toString(); });
      child.stderr.on('data', (d: Buffer) => { stderr += d.toString(); });
      child.on('close', (status) => resolve({ status, stdout, stderr }));
      child.stdin.end(input);
    });
  }

  itE2e('git credential fill gets the token, and approve writes no plaintext file even with store configured', async () => {
    expect((await run('git', ['config', '--global', 'credential.helper', 'store'])).status).toBe(0);

    const install = await run(process.execPath, [CLI_PATH, 'git-credential', 'install', '--host', 'github.com', '--name', 'GITHUB_TOKEN']);
    expect(install.status, install.stderr).toBe(0);
    expect(install.stdout + install.stderr).not.toContain(TOKEN);

    const fill = await run('git', ['credential', 'fill'], 'protocol=https\nhost=github.com\n\n');
    expect(fill.status, fill.stderr).toBe(0);
    expect(fill.stdout).toContain('username=x-access-token\n');
    expect(fill.stdout).toContain(`password=${TOKEN}\n`);

    const approve = await run('git', ['credential', 'approve'], `protocol=https\nhost=github.com\nusername=x-access-token\npassword=${TOKEN}\n\n`);
    expect(approve.status, approve.stderr).toBe(0);
    expect(fs.existsSync(path.join(home, '.git-credentials'))).toBe(false);
    expect(fs.existsSync(path.join(home, '.config', 'git', 'credentials'))).toBe(false);
    expect(fs.readFileSync(path.join(home, '.gitconfig'), 'utf-8')).not.toContain(TOKEN);

    const uninstall = await run(process.execPath, [CLI_PATH, 'git-credential', 'uninstall', '--host', 'github.com']);
    expect(uninstall.status, uninstall.stderr).toBe(0);
    const left = await run('git', ['config', '--global', '--get-regexp', '^credential\\.']);
    expect(left.stdout).toBe('credential.helper store\n');
  });
});
