/**
 * A git credential helper that answers from the secret store (#238).
 *
 * Git asks a credential helper for a username and password over a line
 * protocol on stdin and stdout (gitcredentials(7)). This module answers `get`
 * from one named secret, and installs or removes the global git config entries
 * that point git at it.
 *
 * Nothing here writes a credential value anywhere. `store` and `erase` are
 * accepted and ignored, and `install` puts an empty helper entry ahead of this
 * one, which git reads as "forget the helpers configured so far" for that host.
 * Without it, a `credential.helper=store` set elsewhere would still be handed
 * the token after every successful push and write it to `~/.git-credentials`.
 */

import { spawnSync } from 'child_process';
import { isValidSecretName } from './secret-store';

/** The protocol actions git sends as the helper's last argument. */
export const GIT_PROTOCOL_ACTIONS: readonly string[] = ['get', 'store', 'erase'];

/**
 * Username sent when neither the request nor `--username` names one. GitHub,
 * GitLab and Gitea accept any non-empty username alongside a token; this is
 * the one GitHub documents for app installation tokens.
 */
export const DEFAULT_GIT_USERNAME = 'x-access-token';

/** Most a request is allowed to be. Git sends a few short lines. */
export const MAX_REQUEST_BYTES = 64 * 1024;

export interface HelperMapping {
  /** Host name, with a port when the remote uses one: `github.com`, `git.example.com:8443`. */
  host: string;
  /** Secret store name holding the token. */
  name: string;
  /** Username to send. Optional: see DEFAULT_GIT_USERNAME. */
  username?: string;
}

/**
 * Host names, optionally with a port. No scheme, path, user or whitespace:
 * the value is written into a git config key and into a shell command line
 * that git runs, so it is restricted to characters that need no quoting.
 */
const HOST = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*(:[0-9]{1,5})?$/;

/** Same reason as HOST: the username is part of the helper's command line. */
const USERNAME = /^[A-Za-z0-9._@+][A-Za-z0-9._@+-]*$/;

/**
 * Why a `--host` value cannot be written into git config, or null when it can.
 * This is the shape check alone: `uninstall` uses it, so an entry written
 * before the port range was checked can still be removed.
 */
export function hostShapeProblem(host: string): string | null {
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(host)) {
    return `--host takes a host name, not a URL: use --host ${host.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '').replace(/[/?#].*$/, '')}`;
  }
  if (!HOST.test(host)) {
    return `--host "${host}" is not a host name (letters, digits, dots and dashes, optionally :port)`;
  }
  return null;
}

/**
 * Why a `--host` value cannot be used, or null when it can. A port outside
 * 1-65535 is refused: no HTTPS request can reach that port, so the entry
 * would be written and the helper never asked.
 */
export function hostProblem(host: string): string | null {
  const shape = hostShapeProblem(host);
  if (shape) return shape;
  const port = /:([0-9]+)$/.exec(host)?.[1];
  if (port !== undefined && (Number(port) < 1 || Number(port) > 65535)) {
    return `--host "${host}" has port ${port}; a port is a number from 1 to 65535`;
  }
  return null;
}

/** Why a `--username` value cannot be used, or null when it can. */
export function usernameProblem(username: string): string | null {
  return USERNAME.test(username)
    ? null
    : `--username "${username}" may only hold letters, digits and . _ @ + -`;
}

/** Why a `--name` value cannot be used, or null when it can. */
export function nameProblem(name: string): string | null {
  return isValidSecretName(name)
    ? null
    : `--name "${name}" is not a secret name (letters, digits, dash and underscore)`;
}

// ── Protocol ─────────────────────────────────────────────────────────────────

/**
 * The attributes of one request, up to the blank line that ends it.
 *
 * A Map, not an object, so an attribute called `__proto__` is just an
 * attribute. Array attributes (`capability[]`, `wwwauth[]`) are not needed to
 * answer and are skipped. A repeated attribute keeps its last value, as git
 * does. `url=` is expanded into the parts it names, the way git expands it.
 */
export function parseCredentialRequest(input: string): Map<string, string> {
  const attrs = new Map<string, string>();
  for (const raw of input.split('\n')) {
    const line = raw.endsWith('\r') ? raw.slice(0, -1) : raw;
    if (line === '') break;
    const eq = line.indexOf('=');
    if (eq <= 0) continue;
    const key = line.slice(0, eq);
    if (key.endsWith('[]')) continue;
    attrs.set(key, line.slice(eq + 1));
  }
  const url = attrs.get('url');
  const parts = url === undefined ? null : expandUrl(url);
  if (parts) {
    attrs.set('protocol', parts.protocol);
    attrs.set('host', parts.host);
    if (parts.username) attrs.set('username', parts.username);
  }
  return attrs;
}

/**
 * The parts a `url=` value names, or null when it cannot be read in full: the
 * URL does not parse, or its username holds a percent-escape that does not
 * decode. Nothing is taken from a url= read in part, since a request with its
 * host but not its user would skip the username check.
 */
function expandUrl(url: string): { protocol: string; host: string; username: string } | null {
  try {
    const parsed = new URL(url);
    return {
      protocol: parsed.protocol.replace(/:$/, ''),
      host: parsed.host,
      username: parsed.username ? decodeURIComponent(parsed.username) : '',
    };
  } catch {
    return null;
  }
}

export type RequestMatch =
  | { ours: true; username: string }
  | { ours: false; reason: string };

/**
 * Whether this helper should answer the request, and with which username.
 *
 * It answers only https, so a token is never offered over plain http even if
 * the helper is configured for it by hand. It answers only its own host. And
 * it never answers for a different account than the one asked for: when both
 * the request and `--username` name a user and they differ, git moves on to the
 * next helper or its own prompt. A requested username that the answer could not
 * carry as one line (one decoded from `url=` can hold `%0A`) is not answered,
 * so the reply never gains an attribute the request wrote. Nor is a request
 * whose `url=` cannot be read in full, even beside `protocol=` and `host=`:
 * the user it names is unknown, so it cannot be checked.
 */
export function matchRequest(request: Map<string, string>, mapping: HelperMapping): RequestMatch {
  const url = request.get('url');
  if (url !== undefined && expandUrl(url) === null) {
    return { ours: false, reason: 'the request\'s url= cannot be read in full (it does not parse, or its username does not decode), so the user it names cannot be checked' };
  }
  const protocol = request.get('protocol');
  if (protocol !== 'https') {
    return { ours: false, reason: `the request is for ${protocol ? `protocol ${protocol}` : 'no protocol'}, and this helper answers https only` };
  }
  const host = (request.get('host') ?? '').toLowerCase();
  if (host !== mapping.host.toLowerCase()) {
    return { ours: false, reason: `the request is for ${host || 'no host'}, not ${mapping.host}` };
  }
  const requested = request.get('username');
  const userProblem = requested ? valueProblem(requested) : null;
  if (userProblem) {
    return { ours: false, reason: `the requested username ${userProblem}` };
  }
  if (requested && mapping.username && requested !== mapping.username) {
    return { ours: false, reason: `the request names a different user than --username` };
  }
  return { ours: true, username: requested || mapping.username || DEFAULT_GIT_USERNAME };
}

/**
 * Why a stored value cannot be sent over the protocol, or null.
 *
 * Each attribute is one line, so a line break inside the value would end it
 * early and the rest would be read as attributes of git's choosing. Refusing is
 * the only safe answer: trimming would send a different credential than the
 * one stored, silently.
 */
export function valueProblem(value: string): string | null {
  if (value.length === 0) return 'is empty';
  if (/[\r\n]/.test(value)) return 'holds a line break, which the git credential protocol cannot carry';
  if (value.includes('\0')) return 'holds a NUL character, which the git credential protocol cannot carry';
  return null;
}

/** The reply to `get`: exactly the two attributes git needs. */
export function formatAnswer(username: string, password: string): string {
  return `username=${username}\npassword=${password}\n`;
}

// ── Global git config ────────────────────────────────────────────────────────

export interface GitResult {
  status: number;
  stdout: string;
  stderr: string;
}

/** Runs `git <args>` and returns its result. Injected in tests. */
export type GitRunner = (args: string[]) => GitResult;

/** `git` on PATH, with the caller's environment. */
export const runGit: GitRunner = (args) => {
  const res = spawnSync('git', args, { encoding: 'utf-8', timeout: 10_000 });
  if (res.error) {
    const code = (res.error as NodeJS.ErrnoException).code;
    throw new Error(code === 'ENOENT'
      ? 'git was not found on PATH, so the git config could not be read or changed.'
      : `git could not be run: ${res.error.message}`);
  }
  return { status: res.status ?? 1, stdout: res.stdout ?? '', stderr: res.stderr ?? '' };
};

/** The multi-valued key git reads helpers for one https host from. */
export function helperKey(host: string): string {
  return `credential.https://${host}.helper`;
}

/**
 * The helper entry's value. Git runs a value that starts with `!` as a shell
 * command and appends the action (`get`, `store`, `erase`) as its last word.
 * Every part is validated to need no quoting.
 */
export function helperCommand(cli: string, mapping: HelperMapping): string {
  const user = mapping.username ? ` --username ${mapping.username}` : '';
  return `!${cli} git-credential --host ${mapping.host} --name ${mapping.name}${user}`;
}

const OUR_HELPER = /^!.*\sgit-credential --host (\S+) --name ([A-Za-z0-9_-]+)(?: --username \S+)?$/;

/**
 * True for an entry `install` wrote for this host. Recognised by its shape
 * rather than its whole text, so an entry written under a different command
 * prefix (`npx secretless-ai` against an embedding host's) is still found.
 */
export function isOurHelper(value: string, host: string): boolean {
  const m = OUR_HELPER.exec(value);
  return m !== null && m[1].toLowerCase() === host.toLowerCase();
}

/** Every value of `key` in the global git config, in order; [] when unset. */
export function readGlobalValues(git: GitRunner, key: string): string[] {
  const res = git(['config', '--global', '--null', '--get-all', key]);
  if (res.status === 1 && res.stdout === '') return [];
  if (res.status !== 0) {
    throw new Error(`git config could not read ${key}: ${res.stderr.trim() || `exit ${res.status}`}`);
  }
  const values = res.stdout.split('\0');
  values.pop();
  return values;
}

/**
 * `values` without the entries `install` added for `host`: each helper entry,
 * and the empty entry directly before it. An empty entry anywhere else is the
 * user's own and stays.
 */
export function withoutOurEntries(values: string[], host: string): { kept: string[]; removed: number } {
  const drop = new Set<number>();
  values.forEach((value, i) => {
    if (!isOurHelper(value, host)) return;
    drop.add(i);
    if (i > 0 && values[i - 1] === '' && !drop.has(i - 1)) drop.add(i - 1);
  });
  return { kept: values.filter((_, i) => !drop.has(i)), removed: drop.size };
}

export interface ConfigChange {
  key: string;
  /** False when the config already held exactly what was asked for. */
  changed: boolean;
  /** Values of `key` before and after, in order. */
  before: string[];
  after: string[];
}

function sameList(a: string[], b: string[]): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

/**
 * Replace the values of `key` with `after`.
 *
 * When `after` only extends `before`, the new values are appended and nothing
 * else is touched. Otherwise every value is unset and `after` is written back
 * in order, because git config cannot remove one occurrence of a value that
 * repeats (an empty entry) by position.
 */
function writeValues(git: GitRunner, key: string, before: string[], after: string[]): void {
  const check = (res: GitResult, what: string): void => {
    if (res.status !== 0) {
      throw new Error(`git config could not ${what} ${key}: ${res.stderr.trim() || `exit ${res.status}`}`);
    }
  };
  let start = 0;
  if (after.length >= before.length && sameList(before, after.slice(0, before.length))) {
    start = before.length;
  } else if (before.length > 0) {
    check(git(['config', '--global', '--unset-all', key]), 'remove');
  }
  for (const value of after.slice(start)) {
    check(git(['config', '--global', '--add', key, value]), 'add a value to');
  }
}

/**
 * Point git at this helper for `mapping.host`, in the global git config.
 *
 * Appends an empty entry and the helper entry. An entry this command wrote
 * earlier for the same host is replaced, so re-running with a different
 * `--name` moves the host to the new secret rather than adding a second
 * helper behind the first.
 */
export function installHelper(git: GitRunner, cli: string, mapping: HelperMapping): ConfigChange {
  const key = helperKey(mapping.host);
  const before = readGlobalValues(git, key);
  const after = [...withoutOurEntries(before, mapping.host).kept, '', helperCommand(cli, mapping)];
  if (sameList(before, after)) return { key, changed: false, before, after };
  writeValues(git, key, before, after);
  return { key, changed: true, before, after };
}

/**
 * Remove the entries `installHelper` added for `host`, and nothing else.
 * Another helper configured for the same host, and its own empty entry, stay
 * where they are.
 */
export function uninstallHelper(git: GitRunner, host: string): ConfigChange {
  const key = helperKey(host);
  const before = readGlobalValues(git, key);
  const { kept, removed } = withoutOurEntries(before, host);
  if (removed === 0) return { key, changed: false, before, after: before };
  writeValues(git, key, before, kept);
  return { key, changed: true, before, after: kept };
}
