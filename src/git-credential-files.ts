/**
 * Plaintext git credential files, and the git setting that writes them (#238).
 *
 * Git's `store` helper keeps every credential it is handed in
 * `~/.git-credentials`, one URL per line with the token in it, and git also
 * reads passwords from `~/.netrc`. Hosting tokens are among the most valuable
 * credentials on a developer machine and these files are where they sit
 * unnoticed, so `doctor` and `status` report them.
 *
 * Reports carry counts, line numbers and host names. A username or a value
 * never leaves this module: a token can sit in the username part of a URL
 * (`https://<token>@github.com`), so the whole userinfo is treated as secret.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { spawnSync } from 'child_process';

export type CredentialFileFormat = 'git-credentials' | 'netrc';

export interface PlaintextCredentialFile {
  /** Absolute path. */
  path: string;
  /** `~/`-relative when under the home directory. */
  display: string;
  format: CredentialFileFormat;
  /** 1-based numbers of the lines holding a credential. */
  lines: number[];
  /** Hosts those lines are for, lowercased and sorted. Never a user or a value. */
  hosts: string[];
}

/** A `credential.*helper` setting whose helper is git's plaintext `store`. */
export interface StoreHelperSetting {
  /** The config key, e.g. `credential.helper` or `credential.https://github.com.helper`. */
  key: string;
  /** The setting's whole value, e.g. `store` or `store --file ~/creds`. */
  value: string;
  /** Config file that sets it, `~/`-relative when under home; null when not from a file. */
  origin: string | null;
  /** Absolute path of that file, for a `git config --file` fix; null when not from a file. */
  originPath: string | null;
  /** The file it writes credentials to, `~/`-relative when under home. */
  writes: string;
}

export interface GitCredentialExposure {
  files: PlaintextCredentialFile[];
  /** Files that exist but could not be read, so what they hold is unknown. */
  unreadable: Array<{ display: string; reason: string }>;
  storeHelpers: StoreHelperSetting[];
  /** False when git could not be run, so no helper setting was checked. */
  configChecked: boolean;
  /** Every file looked at, in the order checked. */
  checked: string[];
}

export interface GitCredentialCheckOptions {
  /**
   * Home directory to check. When given, git runs with `HOME` set to it and
   * the system config and any `GIT_CONFIG_*` / `XDG_CONFIG_HOME` override in
   * the environment ignored, so a fixture home is all that is read.
   */
  homeDir?: string;
  /** Runs `git config` and returns its result; injected in tests. */
  runGitConfig?: (args: string[], env: NodeJS.ProcessEnv, cwd: string) => { status: number; stdout: string } | null;
}

/** Larger files are not read: a credential file is a few lines. */
const MAX_FILE_BYTES = 4 * 1024 * 1024;

function displayPath(file: string, home: string): string {
  const rel = path.relative(home, file);
  return rel && !rel.startsWith('..') && !path.isAbsolute(rel) ? `~/${rel.split(path.sep).join('/')}` : file;
}

function expandHome(p: string, home: string): string {
  if (p === '~') return home;
  if (p.startsWith('~/')) return path.join(home, p.slice(2));
  return path.resolve(home, p);
}

/**
 * The host of a `.git-credentials` line that carries userinfo, or null for a
 * line that carries none. The authority runs to the first `/`, `?` or `#`
 * after `://`, and the host follows its LAST `@`, so a raw `@` inside a
 * hand-written password does not move the host into the userinfo.
 */
export function gitCredentialsLineHost(line: string): string | null {
  const m = /^[A-Za-z][A-Za-z0-9+.-]*:\/\/([^/?#\s]*)/.exec(line.trim());
  if (!m) return null;
  const at = m[1].lastIndexOf('@');
  if (at <= 0) return null;
  return m[1].slice(at + 1).toLowerCase();
}

/** Lines of a `.git-credentials` file that hold a credential. */
export function scanGitCredentials(text: string): { lines: number[]; hosts: string[] } {
  const lines: number[] = [];
  const hosts = new Set<string>();
  text.split('\n').forEach((line, i) => {
    const host = gitCredentialsLineHost(line);
    if (host === null) return;
    lines.push(i + 1);
    if (host) hosts.add(host);
  });
  return { lines, hosts: [...hosts].sort() };
}

/**
 * Lines of a `.netrc` file holding a password value.
 *
 * netrc is a stream of whitespace-separated tokens, so a `password` keyword and
 * its value can sit on different lines; the value's line is the one reported.
 * `macdef` bodies run to the next blank line and are skipped, as are lines
 * starting with `#`, which several readers treat as comments.
 */
export function scanNetrc(text: string): { lines: number[]; hosts: string[] } {
  const lines = new Set<number>();
  const hosts = new Set<string>();
  let machine: string | null = null;
  let expect: 'machine' | 'password' | 'value' | 'macdef' | null = null;
  let inMacdef = false;
  text.split('\n').forEach((raw, i) => {
    const line = raw.trim();
    if (inMacdef) {
      if (line === '') inMacdef = false;
      return;
    }
    if (line.startsWith('#')) return;
    for (const token of line.split(/\s+/).filter(Boolean)) {
      if (expect === 'machine') { machine = token.toLowerCase(); expect = null; continue; }
      if (expect === 'password') {
        lines.add(i + 1);
        if (machine) hosts.add(machine);
        expect = null;
        continue;
      }
      if (expect === 'value') { expect = null; continue; }
      if (expect === 'macdef') { expect = null; inMacdef = true; break; }
      switch (token) {
        case 'machine': expect = 'machine'; break;
        case 'default': machine = 'default'; break;
        case 'password': expect = 'password'; break;
        case 'login':
        case 'account': expect = 'value'; break;
        case 'macdef': expect = 'macdef'; break;
        default: break;
      }
    }
  });
  return { lines: [...lines].sort((a, b) => a - b), hosts: [...hosts].sort() };
}

/** True when a helper setting's value names git's plaintext `store` helper. */
export function isStoreHelper(value: string): boolean {
  const helper = value.trim().split(/\s+/)[0] ?? '';
  return helper === 'store' || /(^|[/\\])git-credential-store(\.exe)?$/.test(helper);
}

/** The `--file` a `store` helper writes to, or null for its default. */
export function storeHelperFile(value: string): string | null {
  const words = value.trim().split(/\s+/);
  for (let i = 1; i < words.length; i++) {
    if (words[i].startsWith('--file=')) return words[i].slice('--file='.length) || null;
    if (words[i] === '--file' && words[i + 1]) return words[i + 1];
  }
  return null;
}

function defaultRunGitConfig(args: string[], env: NodeJS.ProcessEnv, cwd: string): { status: number; stdout: string } | null {
  const res = spawnSync('git', args, { encoding: 'utf-8', env, cwd, timeout: 10_000 });
  if (res.error) return null;
  return { status: res.status ?? 1, stdout: res.stdout ?? '' };
}

/**
 * Every helper setting git would read, with the file it comes from.
 * `--show-origin --null` output is `file:<path>\0<key>\n<value>\0` per entry.
 */
function readHelperSettings(
  run: NonNullable<GitCredentialCheckOptions['runGitConfig']>,
  env: NodeJS.ProcessEnv,
  home: string,
): Array<{ key: string; value: string; originPath: string | null }> | null {
  const res = run(['config', '--show-origin', '--null', '--get-regexp', '^credential\\..*helper$'], env, home);
  if (res === null) return null;
  if (res.status === 1) return [];
  if (res.status !== 0) return null;
  const parts = res.stdout.split('\0');
  const out: Array<{ key: string; value: string; originPath: string | null }> = [];
  for (let i = 0; i + 1 < parts.length; i += 2) {
    const origin = parts[i];
    const entry = parts[i + 1];
    const nl = entry.indexOf('\n');
    const key = nl === -1 ? entry : entry.slice(0, nl);
    const value = nl === -1 ? '' : entry.slice(nl + 1);
    out.push({ key, value, originPath: origin.startsWith('file:') ? origin.slice('file:'.length) : null });
  }
  return out;
}

/**
 * Plaintext git credential files under the home directory, and any `store`
 * helper setting. Reads files and runs `git config`; writes nothing.
 */
export function findGitCredentialExposure(options: GitCredentialCheckOptions = {}): GitCredentialExposure {
  const fixture = options.homeDir !== undefined;
  const home = options.homeDir ?? os.homedir();
  const env: NodeJS.ProcessEnv = { ...process.env };
  if (fixture) {
    env.HOME = home;
    env.GIT_CONFIG_NOSYSTEM = '1';
    for (const name of ['XDG_CONFIG_HOME', 'GIT_CONFIG_GLOBAL', 'GIT_CONFIG_SYSTEM', 'GIT_CONFIG_COUNT', 'GIT_CONFIG_PARAMETERS', 'GIT_DIR']) {
      delete env[name];
    }
  }
  const xdgConfig = env.XDG_CONFIG_HOME ? env.XDG_CONFIG_HOME : path.join(home, '.config');

  const settings = readHelperSettings(options.runGitConfig ?? defaultRunGitConfig, env, home);
  const storeHelpers: StoreHelperSetting[] = [];
  const targets: Array<{ file: string; format: CredentialFileFormat }> = [
    { file: path.join(home, '.git-credentials'), format: 'git-credentials' },
    { file: path.join(xdgConfig, 'git', 'credentials'), format: 'git-credentials' },
    { file: path.join(home, '.netrc'), format: 'netrc' },
    { file: path.join(home, '_netrc'), format: 'netrc' },
  ];
  for (const s of settings ?? []) {
    if (!isStoreHelper(s.value)) continue;
    const named = storeHelperFile(s.value);
    const writes = named ? expandHome(named, home) : path.join(home, '.git-credentials');
    if (named) targets.push({ file: writes, format: 'git-credentials' });
    storeHelpers.push({
      key: s.key,
      value: s.value.trim(),
      origin: s.originPath ? displayPath(s.originPath, home) : null,
      originPath: s.originPath,
      writes: displayPath(writes, home),
    });
  }

  const files: PlaintextCredentialFile[] = [];
  const unreadable: GitCredentialExposure['unreadable'] = [];
  const checked: string[] = [];
  const seen = new Set<string>();
  for (const { file, format } of targets) {
    if (seen.has(file)) continue;
    seen.add(file);
    const display = displayPath(file, home);
    checked.push(display);
    let text: string;
    try {
      const st = fs.statSync(file);
      if (!st.isFile()) continue;
      if (st.size > MAX_FILE_BYTES) {
        unreadable.push({ display, reason: `larger than ${MAX_FILE_BYTES / (1024 * 1024)} MB, not read` });
        continue;
      }
      text = fs.readFileSync(file, 'utf-8');
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === 'ENOENT' || code === 'ENOTDIR') continue;
      unreadable.push({ display, reason: code ?? 'could not be read' });
      continue;
    }
    const found = format === 'netrc' ? scanNetrc(text) : scanGitCredentials(text);
    if (found.lines.length > 0) files.push({ path: file, display, format, ...found });
  }

  return { files, unreadable, storeHelpers, configChecked: settings !== null, checked };
}

// ── Presentation ─────────────────────────────────────────────────────────────

export interface ExposureFinding {
  message: string;
  /** The same finding in a few words, for a `status` row. */
  summary: string;
  verify: string;
  fix: string[];
}

/** A name to store a host's token under, so each Fix line runs as printed. */
export function suggestedSecretName(host: string): string {
  const bare = host.replace(/:\d+$/, '');
  const known: Record<string, string> = {
    'github.com': 'GITHUB_TOKEN',
    'gitlab.com': 'GITLAB_TOKEN',
    'bitbucket.org': 'BITBUCKET_TOKEN',
    'codeberg.org': 'CODEBERG_TOKEN',
  };
  return known[bare] ?? `${bare.toUpperCase().replace(/[^A-Z0-9]+/g, '_')}_TOKEN`;
}

function shellArg(p: string): string {
  if (/^(~\/)?[A-Za-z0-9._/:@+=,-]+$/.test(p)) return p;
  const quote = (s: string): string => `'${s.replace(/'/g, `'\\''`)}'`;
  // `~` expands only outside quotes.
  return p.startsWith('~/') ? `~/${quote(p.slice(2))}` : quote(p);
}

function listLines(lines: number[]): string {
  const shown = lines.slice(0, 10).join(', ');
  const more = lines.length > 10 ? ` and ${lines.length - 10} more` : '';
  return `line${lines.length === 1 ? '' : 's'} ${shown}${more}`;
}

/** Host-by-host replacement steps: store the new token, point git at it. */
function moveSteps(hosts: string[], cli: string): string[] {
  if (hosts.length === 0) {
    return [`${cli} secret set <NAME>, then ${cli} git-credential install --host <host> --name <NAME>`];
  }
  return hosts.flatMap((host) => {
    const name = suggestedSecretName(host);
    return [`${cli} secret set ${name}`, `${cli} git-credential install --host ${host} --name ${name}`];
  });
}

/**
 * One finding per exposure, each with a Verify command that prints a count and
 * never a line, and Fix steps that end with the plaintext gone.
 */
export function describeExposure(exposure: GitCredentialExposure, cli: string): ExposureFinding[] {
  const out: ExposureFinding[] = [];
  for (const f of exposure.files) {
    const count = f.lines.length;
    // A netrc `default` entry is the fallback for any machine, not a host or a
    // provider, so it is named in neither list.
    const hosts = f.hosts.filter((h) => h !== 'default');
    const where = hosts.length > 0 ? ` for ${hosts.join(', ')}` : '';
    const what = f.format === 'netrc'
      ? `${count} plaintext password${count === 1 ? '' : 's'}`
      : `${count} plaintext credential line${count === 1 ? '' : 's'}`;
    const file = shellArg(f.display);
    const providers = hosts.length > 0 ? ` (${hosts.join(', ')})` : '';
    const revoke = count === 1
      ? `Revoke that token at the provider${providers} and create a new one`
      : `Revoke those tokens at the provider${providers} and create new ones`;
    const remove = f.format === 'netrc'
      ? `Delete the password entries on those lines, or the file if nothing else reads it: rm ${file}`
      : `rm ${file}`;
    out.push({
      message: `${f.display} holds ${what} (${listLines(f.lines)})${where}`,
      summary: `${f.display}: ${what} (${listLines(f.lines)})`,
      verify: f.format === 'netrc' ? `grep -c password ${file}` : `grep -c @ ${file}`,
      fix: [revoke, ...moveSteps(hosts, cli), remove],
    });
  }
  for (const u of exposure.unreadable) {
    out.push({
      message: `${u.display} exists but was not read (${u.reason}), so whether it holds credentials is unknown`,
      summary: `${u.display}: not read (${u.reason})`,
      verify: `ls -l ${shellArg(u.display)}`,
      fix: [`Make it readable and re-run this check, or delete it: rm ${shellArg(u.display)}`],
    });
  }
  for (const s of exposure.storeHelpers) {
    const from = s.origin ? ` in ${s.origin}` : '';
    const unset = s.origin
      ? `git config --file ${shellArg(s.origin)} --fixed-value --unset-all ${shellArg(s.key)} ${shellArg(s.value)}`
      : `Remove ${s.key}=${s.value} from where it is set`;
    out.push({
      message: `${s.key} is \`${s.value}\`${from}: git writes every credential it uses to ${s.writes} in plaintext`,
      summary: `${s.key}=store${from}: git saves credentials in plaintext`,
      // Only the `store` entry: another value of the same key can be an inline
      // helper with a token written into it.
      verify: `git config --show-origin --fixed-value --get-all ${shellArg(s.key)} ${shellArg(s.value)}`,
      fix: [unset, `For each host you reach over HTTPS: ${cli} git-credential install --host <host> --name <NAME>`],
    });
  }
  return out;
}
