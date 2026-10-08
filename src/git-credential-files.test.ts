/**
 * `doctor` and `status` report plaintext git credential files and a `store`
 * helper (#238): counts, line numbers and hosts, never a user or a value.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  scanGitCredentials,
  scanNetrc,
  gitCredentialsLineHost,
  isStoreHelper,
  storeHelperFile,
  findGitCredentialExposure,
  describeExposure,
  suggestedSecretName,
} from './git-credential-files';

const TOKEN = 'ghp_FAKE7qK2vR9xW4mZ8nB3cJ6hT1yL5pD0sGu';
const NETRC_PW = 'FAKE9wQ3zX7kV2bN5mJ8';
const USER = 'octo-fake-user';
const CLI_PATH = path.resolve(__dirname, '..', 'dist', 'cli.js');
const hasGit = spawnSync('git', ['--version']).status === 0;
const itIfGit = hasGit ? it : it.skip;

/** Every 6-character piece of a secret, so a partial leak is caught too. */
function pieces(secret: string): string[] {
  const out: string[] = [];
  for (let i = 0; i + 6 <= secret.length; i++) out.push(secret.slice(i, i + 6));
  return out;
}

function expectNoPartOf(text: string, secret: string): void {
  for (const piece of pieces(secret)) expect(text, `printed part of a secret: ${piece}`).not.toContain(piece);
}

function gitEnv(home: string): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env, HOME: home, GIT_CONFIG_NOSYSTEM: '1', OPENA2A_TELEMETRY: 'off', NO_COLOR: '1' };
  for (const name of ['XDG_CONFIG_HOME', 'GIT_CONFIG_GLOBAL', 'GIT_CONFIG_SYSTEM', 'GIT_CONFIG_COUNT', 'GIT_CONFIG_PARAMETERS', 'GIT_DIR']) {
    delete env[name];
  }
  return env;
}

describe('plaintext credential file parsers', () => {
  it('counts .git-credentials lines that carry userinfo, by host', () => {
    const text = [
      `https://${USER}:${TOKEN}@github.com`,
      '',
      `https://${TOKEN}@gitlab.com/group`,
      'https://example.org/no-userinfo',
      `https://${USER}:p@ss@GIT.example.com:8443`,
      'not a url',
    ].join('\n');
    expect(scanGitCredentials(text)).toEqual({ lines: [1, 3, 5], hosts: ['git.example.com:8443', 'github.com', 'gitlab.com'] });
    expect(gitCredentialsLineHost('https://@github.com')).toBeNull();
  });

  it('reports the line of each netrc password value, across lines, skipping macdef bodies and comments', () => {
    const text = [
      'machine github.com',
      `  login ${USER}`,
      '  password',
      `  ${NETRC_PW}`,
      `machine api.example.org login a password ${NETRC_PW}`,
      'macdef init',
      `password ${NETRC_PW}`,
      '',
      '# password is in the vault',
      `default login anonymous password ${NETRC_PW}`,
    ].join('\n');
    expect(scanNetrc(text)).toEqual({ lines: [4, 5, 10], hosts: ['api.example.org', 'default', 'github.com'] });
  });

  it('recognises the store helper in its spellings', () => {
    expect(isStoreHelper('store')).toBe(true);
    expect(isStoreHelper('store --file ~/.my-creds')).toBe(true);
    expect(isStoreHelper('/usr/lib/git-core/git-credential-store')).toBe(true);
    expect(isStoreHelper('osxkeychain')).toBe(false);
    expect(isStoreHelper('!gh auth git-credential')).toBe(false);
    expect(isStoreHelper('')).toBe(false);
    expect(storeHelperFile('store --file ~/.my-creds')).toBe('~/.my-creds');
    expect(storeHelperFile('store --file=/tmp/c')).toBe('/tmp/c');
    expect(storeHelperFile('store')).toBeNull();
  });

  it('suggests a runnable secret name per host', () => {
    expect(suggestedSecretName('github.com')).toBe('GITHUB_TOKEN');
    expect(suggestedSecretName('git.example.com:8443')).toBe('GIT_EXAMPLE_COM_TOKEN');
  });
});

describe('findGitCredentialExposure on a fixture home', () => {
  let home: string;
  beforeEach(() => { home = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-gitcred-files-')); });
  afterEach(() => fs.rmSync(home, { recursive: true, force: true }));

  itIfGit('finds nothing in an empty home, and says what it checked', () => {
    const exposure = findGitCredentialExposure({ homeDir: home });
    expect(exposure.files).toEqual([]);
    expect(exposure.storeHelpers).toEqual([]);
    expect(exposure.configChecked).toBe(true);
    expect(exposure.checked).toEqual(['~/.git-credentials', '~/.config/git/credentials', '~/.netrc', '~/_netrc']);
    expect(describeExposure(exposure, 'npx secretless-ai')).toEqual([]);
  });

  itIfGit('reports each file and the store helper with Verify and Fix lines, and no user or value', () => {
    fs.writeFileSync(path.join(home, '.git-credentials'), `https://${USER}:${TOKEN}@github.com\n`);
    fs.writeFileSync(path.join(home, '.netrc'), `machine gitlab.com login ${USER} password ${NETRC_PW}\n`);
    fs.writeFileSync(path.join(home, 'other-creds'), `https://${USER}:${TOKEN}@codeberg.org\n`);
    const git = (args: string[]): void => {
      expect(spawnSync('git', args, { env: gitEnv(home), cwd: home }).status).toBe(0);
    };
    git(['config', '--global', 'credential.helper', 'store']);
    git(['config', '--global', 'credential.https://codeberg.org.helper', 'store --file ~/other-creds']);

    const exposure = findGitCredentialExposure({ homeDir: home });
    expect(exposure.files.map((f) => [f.display, f.lines, f.hosts])).toEqual([
      ['~/.git-credentials', [1], ['github.com']],
      ['~/.netrc', [1], ['gitlab.com']],
      ['~/other-creds', [1], ['codeberg.org']],
    ]);
    expect(exposure.storeHelpers.map((s) => [s.key, s.origin, s.writes])).toEqual([
      ['credential.helper', '~/.gitconfig', '~/.git-credentials'],
      ['credential.https://codeberg.org.helper', '~/.gitconfig', '~/other-creds'],
    ]);

    const findings = describeExposure(exposure, 'npx secretless-ai');
    expect(findings).toHaveLength(5);
    for (const f of findings) {
      expect(f.verify).toBeTruthy();
      expect(f.fix.length).toBeGreaterThan(0);
    }
    expect(findings[0].message).toBe('~/.git-credentials holds 1 plaintext credential line (line 1) for github.com');
    expect(findings[0].verify).toBe('grep -c @ ~/.git-credentials');
    expect(findings[0].fix).toEqual([
      'Revoke that token at the provider (github.com) and create a new one',
      'npx secretless-ai secret set GITHUB_TOKEN',
      'npx secretless-ai git-credential install --host github.com --name GITHUB_TOKEN',
      'rm ~/.git-credentials',
    ]);
    expect(findings[3].fix[0]).toBe("git config --file ~/.gitconfig --fixed-value --unset-all credential.helper store");
    expect(findings[4].verify).toBe("git config --show-origin --fixed-value --get-all credential.https://codeberg.org.helper 'store --file ~/other-creds'");

    const printed = JSON.stringify(findings) + JSON.stringify(exposure);
    expectNoPartOf(printed, TOKEN);
    expectNoPartOf(printed, NETRC_PW);
    expect(printed).not.toContain(USER);
  });
});

/**
 * The acceptance case from the issue, through the built CLI: a fixture home
 * holding a token-shaped `.git-credentials` line and the `store` helper.
 */
describe('doctor and status on a fixture home', () => {
  const hasBuild = fs.existsSync(CLI_PATH);
  const itCli = hasBuild && hasGit ? it : it.skip;

  let home: string;
  beforeEach(() => { home = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-gitcred-doctor-')); });
  afterEach(() => fs.rmSync(home, { recursive: true, force: true }));

  function cli(args: string[]): { status: number | null; stdout: string; stderr: string } {
    const res = spawnSync(process.execPath, [CLI_PATH, ...args], { env: gitEnv(home), cwd: home, encoding: 'utf-8' });
    return { status: res.status, stdout: res.stdout, stderr: res.stderr };
  }

  itCli('doctor flags the file and the store helper, prints no part of the token, and keeps its exit code', () => {
    const clean = cli(['doctor']);
    expect(clean.stdout).toContain('+ No plaintext credential in ~/.git-credentials');
    expect(clean.stdout).toContain('+ No credential.helper set to store');

    fs.writeFileSync(path.join(home, '.git-credentials'), `https://${USER}:${TOKEN}@github.com\n`);
    expect(spawnSync('git', ['config', '--global', 'credential.helper', 'store'], { env: gitEnv(home), cwd: home }).status).toBe(0);

    const res = cli(['doctor']);
    expect(res.status).toBe(clean.status);
    expect(res.stdout).toContain('[WARN] ~/.git-credentials holds 1 plaintext credential line (line 1) for github.com');
    expect(res.stdout).toContain('Verify: grep -c @ ~/.git-credentials');
    expect(res.stdout).toContain('git-credential install --host github.com --name GITHUB_TOKEN');
    expect(res.stdout).toContain('[WARN] credential.helper is `store` in ~/.gitconfig');
    expectNoPartOf(res.stdout + res.stderr, TOKEN);
    expect(res.stdout + res.stderr).not.toContain(USER);
  });

  itCli('status --json carries the file and the setting, never the value', () => {
    fs.writeFileSync(path.join(home, '.git-credentials'), `https://${USER}:${TOKEN}@github.com\n`);
    const project = path.join(home, 'project');
    fs.mkdirSync(project);
    const res = cli(['status', project, '--json']);
    expect(res.status, res.stderr).toBe(0);
    const doc = JSON.parse(res.stdout);
    expect(doc.gitCredentials.files).toHaveLength(1);
    expect(doc.gitCredentials.files[0].display).toBe('~/.git-credentials');
    expect(doc.gitCredentials.files[0].lines).toEqual([1]);
    expect(doc.gitCredentials.configChecked).toBe(true);
    expect(doc.gitCredentials.findings).toHaveLength(1);
    expect(doc.gitCredentials.findings[0].verify).toBe('grep -c @ ~/.git-credentials');
    expect(doc.gitCredentials.findings[0].fix).toContain('rm ~/.git-credentials');
    expectNoPartOf(res.stdout + res.stderr, TOKEN);
    expect(res.stdout).not.toContain(USER);

    const human = cli(['status', project]);
    expect(human.status, human.stderr).toBe(0);
    expect(human.stdout).toMatch(/⚠ ~\/\.git-credentials: 1 plaintext credential line \(line 1\)\s+→ secretless-ai doctor/);
    expectNoPartOf(human.stdout + human.stderr, TOKEN);
  });
});
