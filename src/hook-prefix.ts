/**
 * The command prefix written into a hook or helper that a later process runs:
 * the git pre-commit hook, the Claude Code Stop and UserPromptSubmit hooks
 * and the git credential helper.
 *
 * The prefix names the copy that wrote it, so the hook runs that code from
 * whatever directory git or Claude Code starts it in: the node binary and this
 * package's CLI script as absolute paths, the form the shell hook uses (#333).
 * When those paths cannot be resolved, or the copy runs from the npx cache,
 * which npm may remove, it names the running version exactly and keeps npx on
 * the local npm cache. It is never a bare `npx secretless-ai`.
 *
 * A body that names the copy by path stops working when that copy is gone, so
 * it tests the CLI file first and fails with one line naming the file and the
 * command that reinstalls the hook (`targetCheck`), and `status` reads the
 * same paths back to report it (`missingPrefixTarget`).
 */

import * as fs from 'fs';
import * as path from 'path';
import { shellHookCommand, shellQuote } from './env';
import { VERSION } from './commands/utils';
import { isExactVersion } from './printed-command';

export interface HookPrefixOptions {
  /** The node binary; defaults to the one running. */
  execPath?: string;
  pathEnv?: string;
  /** The CLI script; defaults to `cli.js` beside this module. */
  script?: string;
  /** The version the npx form pins; defaults to this package's. */
  version?: string;
}

/** A path that a shell line or a git config value carries unchanged. */
function writablePath(p: string): boolean {
  return path.isAbsolute(p) && !/[\x00-\x1f\x7f]/.test(p);
}

function isFile(p: string): boolean {
  try {
    return fs.statSync(p).isFile();
  } catch {
    return false;
  }
}

/** True when `script` is this package's CLI: a file whose package.json names `secretless-ai`. */
function isOwnCli(script: string): boolean {
  if (!isFile(script)) return false;
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(path.dirname(script), '..', 'package.json'), 'utf-8'));
    return pkg?.name === 'secretless-ai';
  } catch {
    return false;
  }
}

/**
 * The version goes into a shell line, so only one exact release is accepted;
 * a range, a tag or anything else is refused rather than quoted.
 */
function exactVersion(version: string): string {
  if (!isExactVersion(version)) {
    throw new Error(`Refusing to write "${version}" into a hook: not an exact version.`);
  }
  return version;
}

/**
 * True when `p`, as given or with its links resolved, has an `_npx` directory
 * on it: where npm keeps the packages `npx` installs, under its cache
 * directory, and may remove them. The directory name is the marker; npm
 * documents no other.
 */
function inNpxCache(p: string): boolean {
  const hasSegment = (q: string): boolean => q.split(/[\\/]/).includes('_npx');
  if (hasSegment(p)) return true;
  try {
    return hasSegment(fs.realpathSync(p));
  } catch {
    return false;
  }
}

export interface HookPrefix {
  /** The prefix to write. */
  prefix: string;
  /**
   * The running copy resolved, but from the npx cache, so the versioned npx
   * form was chosen over its path.
   */
  npxCache: boolean;
}

/** The prefix `commandPrefixForHooks` writes, and whether the npx cache decided it. */
export function resolveHookPrefix(options: HookPrefixOptions = {}): HookPrefix {
  const execPath = options.execPath ?? process.execPath;
  const pathEnv = options.pathEnv ?? process.env.PATH ?? '';
  const script = options.script ?? path.join(__dirname, 'cli.js');
  const npx = (npxCache: boolean): HookPrefix => ({
    prefix: `npm_config_offline=true npx --yes secretless-ai@${exactVersion(options.version ?? VERSION)}`,
    npxCache,
  });
  if (writablePath(script) && writablePath(execPath) && isFile(execPath) && isOwnCli(script)) {
    if (inNpxCache(script)) return npx(true);
    const command = shellHookCommand(execPath, pathEnv, script);
    if (command.every(writablePath)) return { prefix: command.map(shellQuote).join(' '), npxCache: false };
  }
  return npx(false);
}

export function commandPrefixForHooks(options: HookPrefixOptions = {}): string {
  return resolveHookPrefix(options).prefix;
}

/** One word as `shellQuote` writes it, its text captured. */
const QUOTED = String.raw`'((?:[^']|'\\'')*)'`;

/** The path form of a prefix: the node binary and the CLI script, each quoted. */
const PATH_FORM = new RegExp(`^${QUOTED} ${QUOTED}$`);

/** The path form ending a hook body up to its subcommand, after the file test when there is one. */
const PATH_FORM_AT_END = new RegExp(`(?:^|; )${QUOTED} ${QUOTED}$`);

function pathFormPaths(m: RegExpExecArray | null): { node: string; cli: string } | null {
  const unquote = (word: string): string => word.replace(/'\\''/g, "'");
  return m === null ? null : { node: unquote(m[1]), cli: unquote(m[2]) };
}

/**
 * The file test a hook body puts before a prefix in the path form: when the
 * CLI script is gone, print one line naming it and the command that
 * reinstalls the hook, and exit with `exitCode` before the prefix runs. Empty
 * for the npx form, which names no file.
 */
export function targetCheck(prefix: string, what: string, reinstall: string, exitCode: 0 | 1): string {
  const paths = pathFormPaths(PATH_FORM.exec(prefix));
  if (paths === null) return '';
  const message = `secretless-ai: ${what} not found at ${paths.cli}. Reinstall: ${reinstall}`;
  return `[ -f ${shellQuote(paths.cli)} ] || { printf '%s\\n' ${shellQuote(message)} >&2; exit ${exitCode}; }; `;
}

/**
 * The first file a hook body names that is missing, its CLI script before its
 * node binary. `head` is the body up to the subcommand. Null when both files
 * exist, and when `head` does not end in the path form, as the npx form does
 * not.
 */
export function missingPrefixTarget(head: string): string | null {
  const paths = pathFormPaths(PATH_FORM_AT_END.exec(head));
  if (paths === null) return null;
  if (!isFile(paths.cli)) return paths.cli;
  if (!isFile(paths.node)) return paths.node;
  return null;
}
